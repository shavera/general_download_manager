"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

from typing import Annotated

from fastapi import Depends, FastAPI

from .dependencies import get_current_active_user
from .models import User
from .internal import admin


app = FastAPI()

app.include_router(admin.router)


@app.get("/users/me/")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]