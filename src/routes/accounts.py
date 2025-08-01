from datetime import datetime, timedelta, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from exceptions.security import InvalidTokenError, TokenExpiredError
from schemas.accounts import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
)
from security.token_manager import JWTAuthManager
from starlette.concurrency import run_in_threadpool
from security.passwords import hash_password, verify_password
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface


router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

ACCESS_TOKEN_EXPIRE_MINUTES = 15

async def get_user_by_email(db: AsyncSession, email: str):
    """Returns user by email"""
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")
    try:
        result = await db.execute(
            select(UserGroupModel)
            .where(UserGroupModel.name == UserGroupEnum.USER)
        )
        group_id = result.scalar_one_or_none()
        hashed = await run_in_threadpool(hash_password, user.password)
        db_user = UserModel(
            email=user.email,
            _hashed_password=hashed,
            group=group_id
        )
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        activation_token = ActivationTokenModel(user=db_user)
        db.add(activation_token)
        await db.commit()
        return db_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate(user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user.is_active == False:
        result = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.user == db_user))
        token = result.scalar_one_or_none()
        if not token:
            raise HTTPException(status_code=400, detail="Invalid or expired activation token.") 
        expires = token.expires_at
        expires = expires.replace(tzinfo=timezone.utc)
        if (token.token != user.token) or (datetime.now(timezone.utc) > expires):
            raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
        db_user.is_active = True
        await db.delete(token)
        await db.commit()
        return {"message": "User account activated successfully."}
    raise HTTPException(status_code=400, detail="User account is already active.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def reset_password(
    user: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    if db_user and db_user.is_active == True:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user == db_user)
        )
        reset_token = PasswordResetTokenModel(user=db_user)
        db.add(reset_token)
        await db.commit()
        return {"message": "If you are registered, you will receive an email with instructions."}
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password_complete(
    user: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    try:
        db_user = await get_user_by_email(db, user.email)
        if not db_user:
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        result = await db.execute(
            select(PasswordResetTokenModel)
            .where(user.email == db_user.email)
        )
        token = result.scalar_one_or_none()
        if not token:
            raise HTTPException(status_code=400, detail="Invalid email or token.") 
        expires = token.expires_at
        expires = expires.replace(tzinfo=timezone.utc)
        if (token.token != user.token) or (datetime.now(timezone.utc) > expires):
            await db.delete(token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        db_user._hashed_password = hash_password(user.password) # type: ignore
        await db.delete(token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
    user: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    try:
        db_user = await get_user_by_email(db, user.email)
        if not db_user or not verify_password(user.password, db_user._hashed_password):
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        if db_user.is_active == False:
            raise HTTPException(status_code=403, detail="User account is not activated.")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expires = timedelta(days=settings.LOGIN_TIME_DAYS)
        access_token = jwt_manager.create_access_token(
            data={"sub": db_user.email, "user_id": db_user.id}, expires_delta=access_token_expires
        )
        refresh_token = jwt_manager.create_refresh_token(
            data={"sub": db_user.email, "user_id": db_user.id}, expires_delta=refresh_token_expires
        )
        await db.execute(
            delete(RefreshTokenModel)
            .where(RefreshTokenModel.user == db_user)
        )
        db_refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(db_refresh_token)
        await db.commit()
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def access_token_refresh(
    user: TokenRefreshRequestSchema,
    db: Session = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(user.refresh_token)
        user_id = payload.get("user_id")
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(status_code=400, detail="Token has expired.")
    result_token = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == user.refresh_token)
    )
    db_token = result_token.scalar_one_or_none()
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    result = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = jwt_manager.create_access_token(
        data={"sub": db_user.email, "user_id": db_user.id}, expires_delta=access_token_expires
    )

    return {"access_token": new_access_token}