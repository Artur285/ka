# app/main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import jwt
import os
from passlib.context import CryptContext

SECRET = os.getenv("SECRET", "dev-secret")
ALGORITHM = "HS256"
ACCESS_EXPIRE_MINUTES = 60

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI(title="InfoSystem API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # set origins in prod
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for demo. Replace with async DB (SQLAlchemy) in production.
USERS = {}
REFRESH_TOKENS = {}

class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    name: str | None = None

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

def hash_password(pw: str) -> str:
    return pwd_ctx.hash(pw)

def verify_password(pw: str, hash_):
    return pwd_ctx.verify(pw, hash_)

def create_access_token(sub: str, expires_delta: timedelta | None = None):
    to_encode = {"sub": sub, "iat": datetime.utcnow().timestamp()}
    if expires_delta:
        to_encode["exp"] = (datetime.utcnow() + expires_delta).timestamp()
    else:
        to_encode["exp"] = (datetime.utcnow() + timedelta(minutes=ACCESS_EXPIRE_MINUTES)).timestamp()
    return jwt.encode(to_encode, SECRET, algorithm=ALGORITHM)

@app.post("/api/v1/auth/register", status_code=201)
def register(data: RegisterIn):
    if data.email in USERS:
        raise HTTPException(status_code=400, detail="Email exists")
    USERS[data.email] = {
        "email": data.email,
        "password_hash": hash_password(data.password),
        "role": "user",
        "created_at": datetime.utcnow().isoformat(),
        "name": data.name
    }
    # send verification email in real app
    return {"message": "Registered. Verify email (stub)."}

class LoginIn(BaseModel):
    email: EmailStr
    password: str

@app.post("/api/v1/auth/login", response_model=Token)
def login(payload: LoginIn):
    user = USERS.get(payload.email)
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access = create_access_token(payload.email)
    refresh = create_access_token(payload.email, expires_delta=timedelta(days=7))
    REFRESH_TOKENS[payload.email] = refresh
    return {"access_token": access}

@app.get("/api/v1/users/me")
def me(token: str = Depends(lambda: None)):
    # In real app decode JWT from Authorization header
    return {"stub": "replace with real auth dependency"}
