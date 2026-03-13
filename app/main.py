"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI

from .models import User
from .internal import admin_db
from .internal.security import get_current_active_user
from .routers import admin, jobs


@asynccontextmanager
async def lifespan(_: FastAPI):
    admin_db.initialize_admin_db()
    yield

app = FastAPI(title="General Download Manager API",
              openapi_url="/api/v1/openapi.json",
              docs_url="/api/v1/docs",
              redoc_url="/api/v1/redoc",
              lifespan=lifespan)

app.include_router(admin.router)
app.include_router(jobs.router)


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