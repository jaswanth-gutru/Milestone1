from pydantic import BaseModel, EmailStr
from typing import Optional


# What data frontend sends when registering
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str  # "client" or "freelancer"

# What data we send back (no password here)
class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: str

    class Config:
        orm_mode = True
# ---------- LOGIN ----------
class UserLogin(BaseModel):
    email: EmailStr
    password: str

# ---------- TOKEN ----------
class Token(BaseModel):
    access_token: str
    token_type: str

class ProfileBase(BaseModel):
    full_name: Optional[str] = None
    bio: Optional[str] = None
    skills: Optional[str] = None

class ProfileUpdate(ProfileBase):
    pass

class ProfileOut(ProfileBase):
    id: int

    class Config:
        orm_mode = True