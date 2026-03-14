from datetime import datetime, timezone
import logging
import os

from sqlmodel import Field, Session, SQLModel, create_engine, select

from .. import models
from . import security

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)


class User(SQLModel, table=True):
    """Internal database model ONLY. Not to be transmitted over API."""
    username: str = Field(primary_key=True)
    scope_str: str  # space-separated list of scopes
    hashed_password: str


class AdminLog(SQLModel, table=True):
    """
    Log of administrative operations.
    """
    timestamp: datetime = Field(primary_key=True)
    initiating_user: str | None = Field(foreign_key="user.username")
    operation: str
    details: str


sqlite_filename = "admin.db"
sqlite_url = f"sqlite:///{sqlite_filename}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

class DBError(RuntimeError):
    pass


def check_user(user: User, username: str, plaintext_pwd: str, scope_str: str):
    return (user.username == username and
            user.scope_str == scope_str and
            security.verify_password(plaintext_pwd, user.hashed_password))


def add_user(initiating_user: str, new_user: models.NewUser) -> str | None:
    """
    Add a new user to the database.

    :param initiating_user: username of admin user being used to create the new user
    :param new_user: info about the new user to be added
    :return: a detail string if the user cannot be added; None if added successfully
    """
    if "script" == new_user.username.lower():
        msg = f"Submitted user with name '{new_user.username}' which is forbidden."
        LOGGER.warning(msg)
        return msg
    scope_str = " ".join(new_user.allowed_scopes)
    with Session(engine) as session:
        search_statement = select(User).where(User.username == new_user.username)
        top_result = session.exec(search_statement).first()
        if top_result is not None:
            if check_user(top_result, new_user.username, new_user.pwd_plaintext, scope_str):
                LOGGER.warning(f"Submitted user {new_user.username}, which already exists as-is in db.")
                # This is okay, so don't need to return an error message
                return None
            else:
                msg = f"User {new_user.username} already exists in db with different info."
                LOGGER.warning(msg)
                return msg
        pwd_hash = security.get_password_hash(new_user.pwd_plaintext)
        new_user = User(username=new_user.username, hashed_password=pwd_hash, scope_str=scope_str)
        session.add(new_user)
        log = AdminLog(
            timestamp = datetime.now(timezone.utc),
            initiating_user = initiating_user,
            operation = "create",
            details = f"User '{new_user.username}' with scopes: '{scope_str}'"
        )
        session.add(log)
        session.commit()
    return None


def update_user(initiating_user: str, user_info: models.NewUser, upsert: bool = False) -> str | None:
    """
    Update an existing user in the database.

    Just consumes the whole of the update info. For instance, it can't distinguish if it should
    update the password or not, it just tries to update everything.

    :param initiating_user: username of admin user being used to update the user
    :param user_info: info about the user to replace existing info
    :param upsert: if True, insert the user as a new user
    :return: a detail string if the user cannot be updated; None if updated successfully
    """
    scope_str = " ".join(user_info.allowed_scopes)
    with Session(engine) as session:
        pwd_hash = security.get_password_hash(user_info.pwd_plaintext)

        search_statement = select(User).where(User.username == user_info.username)
        top_result = session.exec(search_statement).first()

        log = AdminLog(
            timestamp=datetime.now(timezone.utc),
            initiating_user=initiating_user,
            operation="update",
            details=f"User '{user_info.username}' with scopes: '{scope_str}'"
        )

        if top_result is None:
            if not upsert:
                msg = f"Requested update of user '{user_info.username}' which does not exist in the db."
                log.details = f"FAILURE: {msg}"
                session.add(log)
                session.commit()
                LOGGER.warning(msg)
                return msg
            else:
                new_user = User(username=user_info.username, hashed_password=pwd_hash, scope_str=scope_str)
                log.operation = "create"
                log.details = f"User '{user_info.username}' with scopes: '{scope_str}' (created via upsert)"
                session.add(new_user)
        else:
            top_result.scope_str = scope_str
            if not security.verify_password(user_info.pwd_plaintext, top_result.hashed_password):
                # Password has been changed; change it in result, add detail to the log
                top_result.hashed_password = pwd_hash
                log.details += " including a password change."
            session.add(top_result)
        session.add(log)
        session.commit()
    return None


def initialize_admin_db():
    SQLModel.metadata.create_all(engine)
    root_user = os.environ["GEN_DL_ROOT_USER"]
    root_password = os.environ["GEN_DL_ROOT_PASSWORD"]
    all_scopes = [security.ADMIN_SCOPE, security.WRITE_SCOPE, security.READ_SCOPE]
    new_root_user = models.NewUser(username=root_user, pwd_plaintext=root_password, allowed_scopes=all_scopes)
    add_user(initiating_user="SCRIPT", new_user=new_root_user)


def get_user(username: str) -> User | None:
    with Session(engine) as session:
        return session.get(User, username)


def search_users(initiating_user: str, username: str | None) -> list[models.User] | models.User | None:
    def to_model(db_user: User | None) -> models.User | None:
        if db_user is None:
            return None
        scopes = db_user.scope_str.split(" ") if db_user.scope_str else []
        return models.User(username=db_user.username, scopes=scopes)

    userlist: list[models.User] = []
    with Session(engine) as session:
        search_statement = select(User).where(User.username == username) if username is not None else select(User)
        response = session.exec(search_statement)
        userlist = [to_model(resp) for resp in response]
        details = "All users" if username is None else f"Searching for user '{username}'"
        log = AdminLog(
            timestamp = datetime.now(timezone.utc),
            initiating_user = initiating_user,
            operation = "read",
            details = details
        )
        session.add(log)
        session.commit()

    if username is not None:
        if len(userlist) == 0:
            return None
        elif len(userlist) == 1:
            return userlist[0]
        else:
            raise DBError(f"Found {len(userlist)} users with username '{username}' which should not be possible")
    else:
        return None if len(userlist) == 0 else userlist


def delete_user(initiating_user: str, username: str):
    with Session(engine) as session:
        search_statement = select(User).where(User.username == username)
        top_result = session.exec(search_statement).first()
        log = AdminLog(
            timestamp = datetime.now(timezone.utc),
            initiating_user = initiating_user,
            operation = "delete",
            details = f"Deleted user '{username}'"
        )
        if top_result is None:
            # if we can't find the user to delete, that's okay, do nothing instead.
            log.details = f"Requested to delete user '{username}', which does not exist in the db"
            session.add(log)
            LOGGER.warning(log.details)
            session.commit()
            return
        session.delete(top_result)
        session.add(log)
        session.commit()

def log_action(log: AdminLog):
    with Session(engine) as session:
        session.add(log)
        session.commit()
