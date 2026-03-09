import secrets
from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

import schemas
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel, models
)
from database.models.accounts import TokenBaseModel
from exceptions import BaseSecurityError
from schemas import UserRegistrationResponseSchema, MessageResponseSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()

# Write your code here


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel:
    result = await db.execute(
        select(UserModel).where(UserModel.email == email)
    )
    return result.scalar_one_or_none()


@router.post(
    "/register/",
    response_model=schemas.UserRegistrationResponseSchema,
    summary="Register a new user",
    description=("Registers a new user in the system,"
                 " assigns them to the default user group,"
                 " and generates an account activation token."),
    responses={
        201: {
            "description": "User registered successfully."
        },
        409: {
            "description": "A user with the same email already exists."
        },
        500: {
            "description": "An error occurred during user creation"
        }
    },
    status_code=status.HTTP_201_CREATED
)
async def create_user(
        user_data: schemas.UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> schemas.UserRegistrationResponseSchema:
    group_query = select(
        UserGroupModel
    ).where(UserGroupModel.name == UserGroupEnum.USER)
    group_result = await db.execute(group_query)
    default_group = group_result.scalar_one_or_none()

    if not default_group:

        raise Exception("Default user group not found in the database.")

    db_user = await get_user_by_email(db=db, email=user_data.email)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )
    try:
        hashed = hash_password(user_data.password)
        new_user = UserModel(
            email=user_data.email,
            _hashed_password=hashed,
            group_id=default_group.id
        )

        db.add(new_user)
        await db.flush()

        new_token = ActivationTokenModel(user_id=new_user.id)

        db.add(new_token)

        await db.commit()
        await db.refresh(new_user)

        return schemas.UserRegistrationResponseSchema.model_validate(new_user)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activate user account",
    description=("Activates a newly registered user account using the provided"
                 " activation token. The token is validated and deleted upon"
                 " successful activation."),
    responses={
        200: {
            "description": "User account activated successfully."
        },
        400: {
            "description": "Invalid or expired activation token."
        }
    },
    status_code=status.HTTP_200_OK

)
async def activate_email(
        user: schemas.UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> schemas.MessageResponseSchema:

    db_user = await get_user_by_email(db=db, email=user.email)
    if not db_user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )
    if db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == db_user.id,
        ActivationTokenModel.token == user.token
    )
    result = await db.execute(stmt)
    token_record = result.scalar_one_or_none()
    if not token_record:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    token_expires_at = cast(
        datetime,
        token_record.expires_at
    ).replace(tzinfo=timezone.utc)

    if token_expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return schemas.MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request password reset",
    description=("Initiates a password reset process. For security reasons,"
                 " this endpoint always returns a success message regardless"
                 " of whether the email exists in the database."),
    responses={
        200: {
            "description": "If you are registered,"
                           " you will receive an email with instructions."
        }
    },
    status_code=status.HTTP_200_OK
)
async def reset_password(
        user_data: schemas.PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)

) -> schemas.MessageResponseSchema:

    db_user = await get_user_by_email(db=db, email=user_data.email)

    if db_user:
        if db_user.is_active:
            await db.execute(
                delete(
                    PasswordResetTokenModel
                ).where(PasswordResetTokenModel.user_id == db_user.id)
            )
            request = PasswordResetTokenModel(user_id=db_user.id)
            db.add(request)
            await db.commit()

    return schemas.MessageResponseSchema(
        message="If you are registered, "
                "you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Complete password reset",
    description=("Verifies the provided reset token and securely"
                 " updates the user's password. Invalid or expired"
                 " tokens are automatically invalidated."),
    responses={
        200: {
            "description": "Password reset successfully."
        },
        400: {
            "description": "Invalid email or token."
        },
        500: {
            "description": "An error while resetting the password."
        }
    },
    status_code=status.HTTP_200_OK

)
async def reset_password_complete(
        user_data: schemas.PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    db_user = await get_user_by_email(db=db, email=user_data.email)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or token")

    if not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token")

    request = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
    result = await db.execute(request)
    token_record = result.scalar_one_or_none()

    if token_record:
        token_expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

        if token_record.token != user_data.token or token_expires_at < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
    else:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:

        db_user.password = user_data.password

        await db.delete(token_record)
        await db.commit()

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return schemas.MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=schemas.UserLoginResponseSchema,
    summary="Authenticate user",
    description=("Authenticates a user via email and password."
                 " Returns a short-lived JWT access token and a"
                 " long-lived refresh token."),
    responses={
        200: {
            "description": "Successfully logged in."
        },
        401: {
            "description": "Invalid email or password."
        },
        403: {
            "description": "User account is not activated."
        },
        500: {
            "description": "An error occurred while processing the request."
        }
    },
    status_code=status.HTTP_200_OK
)
async def user_login(
        user_data: schemas.UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
) -> schemas.UserLoginResponseSchema:
    db_user = await get_user_by_email(db=db, email=user_data.email)

    if not db_user or not db_user.verify_password(user_data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        payload = {"sub": str(db_user.id)}
        refresh_token = jwt_manager.create_refresh_token(data=payload)
        access_token = jwt_manager.create_access_token(data=payload)
        db_refresh_model = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(db_refresh_model)
        await db.commit()
        await db.refresh(db_refresh_model)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )

    return schemas.UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post(
    "/api/v1/accounts/refresh/",
    response_model=schemas.TokenRefreshResponseSchema,
    summary="Refresh access token",
    description=("Generates a new JWT access token using a valid refresh"
                 " token. Validates the token's existence in the database"
                 " and the user's current status."),
    responses={
        200: {
            "description": "Access token successfully refreshed"
        },
        400: {
            "description": "The provided refresh token is invalid or expired."
        },
        401: {
            "description": "The provided refresh token does not exist in the database."
        },
        404: {
            "description": "The user associated with the refresh token does not exist."
        }
    },
    status_code=status.HTTP_200_OK
)
async def refresh_access_token(
        user_data: schemas.TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> schemas.TokenRefreshResponseSchema:

    try:
        db_token = jwt_manager.decode_refresh_token(user_data.refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")

    request = await db.execute(
        select(
            RefreshTokenModel
        ).where(RefreshTokenModel.token == user_data.refresh_token)
    )
    token = request.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = db_token.get("sub")
    if not user_id:
        raise HTTPException(status_code=404, detail="User not found.")

    user_request = await db.execute(
        select(UserModel).where(UserModel.id == int(user_id))
    )
    db_user = user_request.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    payload = {"sub": str(db_user.id)}
    new_access_token = jwt_manager.create_access_token(data=payload)

    return schemas.TokenRefreshResponseSchema(access_token=new_access_token)
