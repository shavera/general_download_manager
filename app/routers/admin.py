"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

from datetime import timedelta
import logging
from typing import Annotated

from fastapi import Depends, HTTPException, status, APIRouter, Security
from fastapi.security import OAuth2PasswordRequestForm

from app.models import Token, NewUser, User
from app.internal.security import (authenticate_user, create_access_token, get_current_user,
                                   ACCESS_TOKEN_EXPIRE_MINUTES, ADMIN_SCOPE)
# from app.internal.admin_db import (add_user, search_users, update_user, DBError, User as DB_User)
from app.internal import admin_db as db

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

AdminDep = Annotated[User, Security(get_current_user, scopes=[ADMIN_SCOPE])]

@router.post("/token")
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(form_data.username, form_data.password, form_data.scopes)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid login information",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "scope": " ".join(form_data.scopes)},
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


@router.post("/create_user")
async def create_user(admin_user: AdminDep, new_user: NewUser) -> User:
    err_detail = db.add_user(admin_user.username, new_user)
    if err_detail is None:
        return User(username=new_user.username, scopes=new_user.allowed_scopes)
    else:
        raise HTTPException(status.HTTP_409_CONFLICT, err_detail)


@router.get("/users")
async def get_users(admin_user: AdminDep, name: str | None = None) -> list[User] | User | None:
    try:
        result = db.search_users(admin_user.username, username=name)
        if result is None:
            msg = "No users found" if name is None else f"User {name} not found"
            raise HTTPException(status.HTTP_404_NOT_FOUND, msg)
    except db.DBError as err:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, err)


@router.post("/update_user")
async def update_user(admin_user: AdminDep, user_info: NewUser, upsert: bool = False) -> User:
    err_detail = db.update_user(admin_user.username, user_info, upsert=upsert)
    if err_detail is None:
        return User(username=user_info.username, scopes=user_info.allowed_scopes)
    else:
        raise HTTPException(status.HTTP_409_CONFLICT, err_detail)


@router.put("/delete_user")
async def delete_user(admin_user: AdminDep, username: str):
    raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "Haven't implemented delete user yet.")
