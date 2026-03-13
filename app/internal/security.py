"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash

from .. import models
from . import admin_db

LOGGER=logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "19b158d65a431b5c8b6679d8d0d095b10dfc3443af53b64e0ef6a306e68ced55"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


ADMIN_SCOPE = "admin"
WRITE_SCOPE = "write"
READ_SCOPE = "read"

password_hash = PasswordHash.recommended()

DUMMY_HASH = password_hash.hash("dummypassword")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="admin/token",
    scopes={ADMIN_SCOPE: "Create and modify users permitted to use API",
            WRITE_SCOPE: "Create new download jobs",
            READ_SCOPE: "Read status of existing download jobs"}
)

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password):
    return password_hash.hash(password)


def authenticate_user(username: str, password: str, scopes: list[str]) -> models.User | None:
    db_user = admin_db.get_user(username)
    if not db_user:
        LOGGER.debug(f"User {username} not found")
        verify_password(password, DUMMY_HASH)
        return None
    if not verify_password(password, db_user.hashed_password):
        LOGGER.debug(f"User submitted incorrect password")
        return None
    db_user_scopes = db_user.scope_str.split(" ")
    for check_for_scope in scopes:
        if check_for_scope not in db_user_scopes:
            LOGGER.warning(f"User '{username}' requested scope '{check_for_scope}' for which they are not permitted.")
            return None
    return models.User(username=username, scopes=scopes)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
        security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]) -> models.User:
    if security_scopes.scopes:
        authenticate_value = f"Bearer scope={security_scopes.scope_str}"
    else:
        authenticate_value = "Bearer"
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": authenticate_value},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scope_str: str = payload.get("scope", "")
        token_scopes = token_scope_str.split(" ")
        token_data = models.TokenData(scopes=token_scopes, username=username)
    except InvalidTokenError:
        raise credentials_exception
    db_user: admin_db.User = admin_db.get_user(username=token_data.username)
    if db_user is None:
        raise credentials_exception

    user_permitted_scopes = token_data.scopes
    scopes_from_get_user = security_scopes.scopes
    for check_for_scope in scopes_from_get_user:
        if check_for_scope not in user_permitted_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient user scope permissions",
                headers={"WWW-Authenticate": authenticate_value},
            )
    # Return a models user with scopes as they're provided from the token
    return models.User(username=db_user.username, scopes=token_data.scopes)

# Would tweak this / break it into a few versions to things like 'get_current_admin_user', e.g.
# by passing different sets of scopes
# This current iteration just tries to get _some_ version of the user.
async def get_current_active_user(
    current_user: Annotated[models.User, Security(get_current_user, scopes=[])],
):
    if len(current_user.scopes) == 0:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
