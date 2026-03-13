import logging
import os

from sqlmodel import Field, Session, SQLModel, create_engine, select

from ..models import NewUser, User as ModelUser
from . import security

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

class User(SQLModel, table=True):
    """Internal database model ONLY. Not to be transmitted over API."""
    username: str = Field(primary_key=True)
    scope_str: str # space-separated list of scopes
    hashed_password: str


sqlite_filename = "admin.db"
sqlite_url = f"sqlite:///{sqlite_filename}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

def check_user(user: User, username: str, plaintext_pwd: str, scope_str: str):
    return (user.username == username and
            user.scope_str == scope_str and
            security.verify_password(plaintext_pwd, user.hashed_password))

def add_user(new_user: NewUser) -> bool:
    scope_str = " ".join(new_user.allowed_scopes)
    with Session(engine) as session:
        search_statement = select(User).where(User.username == new_user.username)
        top_result = session.exec(search_statement).first()
        if top_result is not None:
            if check_user(top_result, new_user.username, new_user.pwd_plaintext, scope_str):
                LOGGER.warning(f"Submitted user {new_user.username}, which already exists as-is in db.")
                return True
            else:
                LOGGER.warning(f"User {new_user.username} already exists in db with different info.")
                LOGGER.warning("User update operation not yet implemented.")
                return False
        pwd_hash = security.get_password_hash(new_user.pwd_plaintext)
        new_user = User(username=new_user.username, hashed_password=pwd_hash, scope_str=scope_str )
        session.add(new_user)
        session.commit()
    return True

def initialize_admin_db():
    SQLModel.metadata.create_all(engine)
    root_user = os.environ["GEN_DL_ROOT_USER"]
    root_password = os.environ["GEN_DL_ROOT_PASSWORD"]
    all_scopes = [security.ADMIN_SCOPE, security.WRITE_SCOPE, security.READ_SCOPE]
    new_root_user = NewUser(username=root_user, pwd_plaintext=root_password, allowed_scopes=all_scopes)
    add_user(new_root_user)


def get_user(username: str) -> User | None:
    with Session(engine) as session:
        return session.get(User, username)
