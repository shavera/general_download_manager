"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

from datetime import timedelta
import logging
from typing import Annotated

from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordRequestForm

from ..dependencies import get_current_active_user
from ..models import Token, NewUser, User
from .security import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from .admin_db import add_user

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


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


@router.post("/create_user/")
async def create_user(admin_user: Annotated[User, Depends(get_current_active_user)], new_user: NewUser) -> User:
    if "admin" not in admin_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not Admin user")
    if add_user(new_user):
        return User(username=new_user.username, scopes=new_user.allowed_scopes)
    else:
        raise HTTPException(status.HTTP_409_CONFLICT, f"User {new_user.username} already exists.")
