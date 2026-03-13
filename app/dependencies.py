"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

from typing import Annotated

from fastapi import Depends, HTTPException

from .models import User
from .internal.security import get_current_user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user