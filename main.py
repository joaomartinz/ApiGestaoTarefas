from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
import jwt
from jwt import PyJWKError
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text, Boolean
from sqlalchemy.orm import sessionmaker, relationship, declarative_base, Session
import uuid 
import asyncio
import socketio
import os

# === Config === 
JWT_SECRET = os.environ.get("JWT-SECRET", "dev-secret-change-me")
JWT_ALGORITHM = "HS256"
ACESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./taskboard.db")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")

# === DB ===
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in  DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bin=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    boards = relationship("Board", back_populates="owner")

class Board(Base):
    __tablename__ = "boards"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("BoardColumn", back_populates="board")

class BoardColumn(Base):
    __tablename__ = "columns"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    position = Column(Integer, default=0)
    board_id = Column(Integer, ForeignKey("boards.id"))
    board = relationship("Board", back_populates="columns")
    cards = relationship("Card", back_populates="column")

class Card(Base):
    __tablename__ = "cards"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    position = Column(Integer, default=0)
    column_id = Column(Integer, ForeignKey("columns.id"))
    column = relationship("BoardColumn", back_populates="cards")

class InviteToken(Base):
    __tablename__ = "invite_tokens"
    id = Column(Integer, primary_key=True, index=True)
    board_id = Column(Integer, ForeignKey("boards.id"))
    email = Column(String, nullable=False)
    token = Column(String, unique=True, index=True, default=lambda: str(uuid.uuid4()))
    expires_at = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(days=1))
    accepted = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# === Sessão do banco ===
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally: 
        db.close()

# === Hash de senha === 
pwd_context = CryptContext(schemes=["bcrypt"], Deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# === JWT === 
oauth_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode,JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(token: str = Depends(oauth_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=JWT_ALGORITHM)
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid token",
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user

# Auth Schemas ===
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: EmailStr

    class config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# === Board / Column / Card Schemas === 
class CardCreate(BaseModel):
    title: str
    description: Optional[str] = None
    position: Optional[int] = 0

class CardOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    position: int

class ColumnCreate(BaseModel):
    title: str
    position: Optional[int] = 0

class ColumnOut(BaseModel):
    id: int
    title: str
    position: int
    card: List[CardOut] = []

    class config: 
        orm_mode = True

class BoardCreate(BaseModel):
    title: str

class BoardOut(BaseModel):
    id: int
    title: str
    owner: UserOut
    columns: List[ColumnOut] = []

    class config: 
        orm_mode = True

# === Invite Schemas ===
class InviteCreate(BaseModel):
    email: EmailStr

class InviteOut(BaseModel):
    id: int
    email: EmailStr
    token: str
    expires_at: str
    accepted: bool

    class config:
        orm_mode = True

