from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
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
from exceptions.security import TokenExpiredError, InvalidTokenError
from security.interfaces import JWTAuthManagerInterface
from schemas import accounts as schemas

router = APIRouter()


@router.post("/register/", response_model=schemas.UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(
        user_data: schemas.UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        stmt = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(stmt)
        if result.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        group_result = await db.execute(group_stmt)
        group = group_result.scalars().first()

        if not group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found."
            )

        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, group.id)
        )
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)
        return {"id": user.id, "email": user.email}
    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=schemas.MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate(
        activation_data: schemas.UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token_record = user.activation_token
    if not token_record or token_record.token != activation_data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        delete_stmt = delete(ActivationTokenModel).where(ActivationTokenModel.id == token_record.id)
        await db.execute(delete_stmt)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    delete_stmt = delete(ActivationTokenModel).where(ActivationTokenModel.id == token_record.id)
    await db.execute(delete_stmt)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation."
        )

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=schemas.MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset(
        reset_data: schemas.PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    success_message = {"message": "If you are registered, you will receive an email with instructions."}

    stmt = select(UserModel).where(UserModel.email == reset_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user and user.is_active:
        delete_stmt = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        await db.execute(delete_stmt)

        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(reset_token)

        try:
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            # Still return success to prevent leak, or should we return 500?
            # README says "always respond with success" to prevent leaks.
            return success_message

    return success_message


@router.post("/reset-password/complete/", response_model=schemas.MessageResponseSchema, status_code=status.HTTP_200_OK)
async def reset_password_complete(
        reset_data: schemas.PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == reset_data.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_record = user.password_reset_token
    if not token_record or token_record.token != reset_data.token:
        if token_record:
            delete_stmt = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_record.id)
            await db.execute(delete_stmt)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        delete_stmt = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_record.id)
        await db.execute(delete_stmt)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = reset_data.password
        delete_stmt = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_record.id)
        await db.execute(delete_stmt)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=schemas.UserLoginResponseSchema, status_code=status.HTTP_200_OK)
async def login(
        login_data: schemas.UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    stmt = select(UserModel).where(UserModel.email == login_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    user_id = cast(int, user.id)
    access_token = jwt_manager.create_access_token({"user_id": user_id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user_id})

    refresh_token_record = RefreshTokenModel.create(
        user_id=user_id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token
    )
    db.add(refresh_token_record)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh/", response_model=schemas.TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_token(
        refresh_data: schemas.TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token.")

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_data.refresh_token)
    result = await db.execute(stmt)
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    user_id = payload.get("user_id")
    if token_record.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    user_stmt = select(UserModel).where(UserModel.id == user_id)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": user.id})
    return {"access_token": new_access_token}
