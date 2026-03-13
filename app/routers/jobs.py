"""
Copyright Alex Shaver 2026 - AGPLv3.0
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Security

from app.models import User, JobSubmission, JobInfo
from app.internal.security import (get_current_user, WRITE_SCOPE, READ_SCOPE)

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

router = APIRouter(prefix="/api/v1/jobs", tags=["Job Management"])

WriteDep = Annotated[User, Security(get_current_user, scopes=[WRITE_SCOPE])]
ReadDep = Annotated[User, Security(get_current_user, scopes=[READ_SCOPE])]

@router.post("/create")
async def create_job(user: WriteDep, submission: JobSubmission) -> JobInfo:
    LOGGER.info(f"Placeholder to create job:\n{user.username}\n{submission}")
    return JobInfo(id=0, url=submission.url, file_path=submission.file_path, status="unhandled")

@router.get("/status")
async def read_job(current_user: ReadDep, id: int) -> JobInfo:
    LOGGER.info(f"Placeholder to read job:\n{current_user.username}\n{id}")
    return JobInfo(id=0, url="fake/url", file_path="fake/file/path", status="unhandled")
