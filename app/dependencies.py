"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

from typing import Annotated

from fastapi import Security, HTTPException

from .models import User
from .internal.security import get_current_user, ADMIN_SCOPE, WRITE_SCOPE, READ_SCOPE


# Would tweak this / break it into a few versions to things like 'get_current_admin_user', e.g.
# by passing different sets of scopes
# This current iteration just tries to get _some_ version of the user.
async def get_current_active_user(
    current_user: Annotated[User, Security(get_current_user, scopes=[])],
):
    if len(current_user.scopes) == 0:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user