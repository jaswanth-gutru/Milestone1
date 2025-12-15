from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials
from jose import JWTError, jwt

from database import Base, engine, SessionLocal
import models
from schemas import (
    UserCreate,
    UserOut,
    UserLogin,
    Token,
    ProfileUpdate,
    ProfileOut,
)
from auth_utils import (
    hash_password,
    verify_password,
    create_access_token,
    SECRET_KEY,
    ALGORITHM,
)

app = FastAPI()

# Create tables (temporary database)
Base.metadata.create_all(bind=engine)

# HTTP Bearer auth (expects "Authorization: Bearer <token>")
security = HTTPBearer()


# Dependency: DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Dependency: get current user from JWT token
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # find user in DB
    user = db.query(models.User).filter(models.User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception

    return user


# Helper for role-based access
def require_role(current_user: models.User, allowed_roles: list[str]):
    if current_user.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this resource",
        )


@app.get("/")
def home():
    return {"message": "Backend is working!"}


# ---------- AUTH ----------

@app.post("/register", response_model=UserOut)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    # 1. Check role
    role = user_data.role.lower()
    if role not in ["client", "freelancer"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role must be 'client' or 'freelancer'",
        )

    # 2. Check if email already exists
    existing_user = (
        db.query(models.User)
        .filter(models.User.email == user_data.email)
        .first()
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # 3. Hash password
    hashed_pw = hash_password(user_data.password)

    # 4. Create user object
    new_user = models.User(
        email=user_data.email,
        hashed_password=hashed_pw,
        role=role,
    )

    # 5. Save to DB
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@app.post("/login", response_model=Token)
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    # 1. Find user by email
    user = (
        db.query(models.User)
        .filter(models.User.email == user_data.email)
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # 2. Check password
    if not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # 3. Create JWT token
    access_token = create_access_token(
        data={"sub": str(user.id), "role": user.role}
    )

    # 4. Return token
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me", response_model=UserOut)
def read_me(current_user: models.User = Depends(get_current_user)):
    # current_user is the user from the token
    return current_user


# ---------- PROFILE ----------

@app.get("/profile", response_model=ProfileOut | None)
def get_profile(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # If profile doesn't exist yet, return None
    if not current_user.profile:
        return None
    return current_user.profile


@app.put("/profile", response_model=ProfileOut)
def update_profile(
    profile_data: ProfileUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # If user has no profile yet, create one
    if not current_user.profile:
        profile = models.Profile(
            full_name=profile_data.full_name,
            bio=profile_data.bio,
            skills=profile_data.skills,
            user_id=current_user.id,
        )
        db.add(profile)
    else:
        profile = current_user.profile
        profile.full_name = profile_data.full_name
        profile.bio = profile_data.bio
        profile.skills = profile_data.skills

    db.commit()
    db.refresh(profile)
    return profile


# ---------- ROLE-BASED ENDPOINTS ----------

@app.get("/client/dashboard")
def client_dashboard(current_user: models.User = Depends(get_current_user)):
    require_role(current_user, ["client"])
    return {"message": f"Welcome client {current_user.email}!"}


@app.get("/freelancer/dashboard")
def freelancer_dashboard(current_user: models.User = Depends(get_current_user)):
    require_role(current_user, ["freelancer"])
    return {"message": f"Welcome freelancer {current_user.email}!"}
