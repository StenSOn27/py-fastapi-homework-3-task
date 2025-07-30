from typing import Optional
from pydantic import BaseModel, EmailStr, field_validator
from database.validators.accounts import validate_email, validate_password_strength
from security.token_manager import JWTAuthManager


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def password_validate(cls, password):
        return validate_password_strength(password=password)
    
    @field_validator("email")
    @classmethod
    def email_validate(cls, email):
        return validate_email(user_email=email)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: Optional[str]


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: Optional[str]


class UserLoginResponseSchema(BaseModel):
    access_token: Optional[str]
    refresh_token: Optional[str]
    token_type: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str
