from datetime import datetime, timedelta
from typing import Optional

from jose import jwt
from passlib.context import CryptContext

# ---------- PASSWORD HASHING (sha256_crypt) ----------
pwd_context = CryptContext(
    schemes=["sha256_crypt"],
    deprecated="auto",
)

def hash_password(password: str) -> str:
    password = str(password)
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_password = str(plain_password)
    return pwd_context.verify(plain_password, hashed_password)

# ---------- JWT CONFIG ----------
SECRET_KEY = "supersecretkey-change-this-later"  # just for dev
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
