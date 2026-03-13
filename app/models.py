"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

from typing import Any

from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None
    scopes: list[str] = []


class User(BaseModel):
    username: str
    scopes: list[str] = []


class NewUser(BaseModel):
    username: str
    pwd_plaintext: str
    allowed_scopes: list[str] = []

class JobSubmission(BaseModel):
    url: str
    file_path: str
    session_id: int | None = None
    metadata: dict[str, Any] | None = None

class JobInfo(BaseModel):
    id: int
    url: str
    file_path: str
    status: str
    progress: float | None = None
