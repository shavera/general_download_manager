"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

from typing import Annotated

from fastapi import Security, HTTPException

from .models import User
from .internal.security import get_current_user, ADMIN_SCOPE, WRITE_SCOPE, READ_SCOPE


