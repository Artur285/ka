# app.py
"""
Single-file information system.
Save as app.py
Install:
    pip install fastapi "uvicorn[standard]" sqlalchemy passlib[bcrypt] pyjwt python-multipart jinja2
Run:
    uvicorn app:app --reload
Visit:
    http://127.0.0.1:8000
Notes:
    - This is a minimal demo. Use secrets and DB migrations for production.
    - Files are saved to ./uploads
"""

import os
import pathlib
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import (
    FastAPI, Request, HTTPException, status, Depends, UploadFile, File, Form
)
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from passlib.context import CryptContext
import jwt
from jinja2 import Template

# ---------------------------
# Config
# ---------------------------
BASE_DIR = pathlib.Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
DATABASE_URL = f"sqlite:///{BASE_DIR / 'app.db'}"
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")  # change in prod
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# ---------------------------
# Database
# ---------------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    name = Column(String, nullable=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    body = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    author = relationship("User", backref="posts")


class FileRecord(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    path = Column(String, nullable=False)
    uploader_id = Column(Integer, ForeignKey("users.id"))
    uploaded_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

# ---------------------------
# Auth & utils
# ---------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # not used by frontend directly


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = {"sub": subject, "iat": datetime.utcnow().timestamp()}
    if expires_delta:
        to_encode["exp"] = (datetime.utcnow() + expires_delta).timestamp()
    else:
        to_encode["exp"] = (datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_access_token(token)
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db.query(User).filter(User.email == sub).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ---------------------------
# Schemas
# ---------------------------


class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class PostOut(BaseModel):
    id: int
    title: str
    body: str
    author: Optional[str]
    created_at: datetime

    class Config:
        orm_mode = True


# ---------------------------
# App
# ---------------------------
app = FastAPI(title="Single-file InfoSystem")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


# ---------------------------
# Routes - API
# ---------------------------

@app.post("/api/register", status_code=201)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        name=payload.name,
        is_admin=False
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "registered", "email": user.email}


@app.post("/api/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user.email)
    return {"access_token": token}


@app.get("/api/me")
def me(current: User = Depends(get_current_user)):
    return {"id": current.id, "email": current.email, "name": current.name, "is_admin": current.is_admin}


@app.post("/api/posts", response_model=PostOut)
def create_post(title: str = Form(...), body: str = Form(...), current: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    post = Post(title=title, body=body, author_id=current.id)
    db.add(post)
    db.commit()
    db.refresh(post)
    return PostOut.from_orm(post)


@app.get("/api/posts", response_model=List[PostOut])
def list_posts(q: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Post).order_by(Post.created_at.desc())
    if q:
        qlike = f"%{q}%"
        query = query.filter((Post.title.ilike(qlike)) | (Post.body.ilike(qlike)))
    posts = query.all()
    results = []
    for p in posts:
        author = p.author.name if p.author else None
        results.append(PostOut(
            id=p.id, title=p.title, body=p.body, author=author, created_at=p.created_at
        ))
    return results


@app.get("/api/posts/{post_id}", response_model=PostOut)
def get_post(post_id: int, db: Session = Depends(get_db)):
    p = db.query(Post).filter(Post.id == post_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Post not found")
    author = p.author.name if p.author else None
    return PostOut(id=p.id, title=p.title, body=p.body, author=author, created_at=p.created_at)


@app.post("/api/upload")
def upload_file(file: UploadFile = File(...), current: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Basic validation
    if file.spool_max_size and file.spool_max_size > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large")
    filename = f"{int(datetime.utcnow().timestamp())}_{file.filename}"
    path = UPLOAD_DIR / filename
    with open(path, "wb") as f:
        content = file.file.read()
        f.write(content)
    rec = FileRecord(filename=file.filename, path=str(path.name), uploader_id=current.id)
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return {"id": rec.id, "url": f"/uploads/{path.name}", "filename": rec.filename}


# ---------------------------
# Frontend - Single Page
# ---------------------------

INDEX_HTML = Template(r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>InfoSystem - single file</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial;max-width:900px;margin:24px auto;padding:0 12px}
    header{display:flex;justify-content:space-between;align-items:center}
    input,textarea{width:100%;padding:8px;margin:4px 0}
    .post{border:1px solid #ddd;padding:12px;margin:12px 0;border-radius:6px}
    .small{font-size:0.9em;color:#666}
    nav a{margin-right:12px}
    button{padding:8px 12px}
  </style>
</head>
<body>
<header>
  <h1>InfoSystem</h1>
  <div id="auth">
    <a href="#" id="show-login">Login</a>
    <a href="#" id="show-register">Register</a>
    <a href="#" id="logout" style="display:none">Logout</a>
  </div>
</header>

<section id="alerts"></section>

<section id="auth-forms" style="margin-top:12px"></section>

<section id="create-post" style="display:none;margin-top:18px">
  <h3>Create post</h3>
  <form id="post-form">
    <input name="title" placeholder="Title" required/>
    <textarea name="body" rows="4" placeholder="Body" required></textarea>
    <button>Create</button>
  </form>
  <h4>Upload file</h4>
  <form id="upload-form">
    <input type="file" name="file" required/>
    <button>Upload</button>
  </form>
  <div id="uploads"></div>
</section>

<section style="margin-top:18px">
  <h3>Posts</h3>
  <input id="search" placeholder="search"/>
  <button id="do-search">Search</button>
  <div id="posts"></div>
</section>

<script>
const api = (path, opts={})=>fetch(path,opts).then(async r=>{
  const t = await r.text();
  try{ return JSON.parse(t) }catch(e){ return t }
});

function setAlert(msg){ document.getElementById('alerts').innerText = msg; setTimeout(()=>document.getElementById('alerts').innerText='',4000) }

function getToken(){ return localStorage.getItem('token') }
function setToken(t){ if(t) localStorage.setItem('token',t); else localStorage.removeItem('token') }

async function renderPosts(q=''){
  const url = q?`/api/posts?q=${encodeURIComponent(q)}`:'/api/posts';
  const posts = await api(url);
  const el = document.getElementById('posts');
  el.innerHTML = '';
  for(const p of posts){
    const d = document.createElement('div'); d.className='post';
    d.innerHTML = `<strong>${p.title}</strong> <div class="small">by ${p.author||'unknown'} • ${new Date(p.created_at).toLocaleString()}</div><p>${p.body}</p>`;
    el.appendChild(d);
  }
}

document.getElementById('do-search').addEventListener('click', ()=>renderPosts(document.getElementById('search').value));

document.getElementById('show-login').addEventListener('click', async (e)=>{
  e.preventDefault();
  document.getElementById('auth-forms').innerHTML = `
    <h3>Login</h3>
    <form id="login-form">
      <input name="email" placeholder="email" required />
      <input name="password" placeholder="password" type="password" required />
      <button>Login</button>
    </form>`;
  document.getElementById('login-form').addEventListener('submit', async ev=>{
    ev.preventDefault();
    const f = new FormData(ev.target);
    const body = {email: f.get('email'), password: f.get('password')};
    const res = await fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    if(!res.ok){ setAlert('Login failed'); return; }
    const j = await res.json();
    setToken(j.access_token);
    document.getElementById('auth-forms').innerHTML='';
    document.getElementById('show-login').style.display='none';
    document.getElementById('show-register').style.display='none';
    document.getElementById('logout').style.display='inline';
    document.getElementById('create-post').style.display='block';
    setAlert('Logged in');
  });
});

document.getElementById('show-register').addEventListener('click', async (e)=>{
  e.preventDefault();
  document.getElementById('auth-forms').innerHTML = `
    <h3>Register</h3>
    <form id="register-form">
      <input name="email" placeholder="email" required />
      <input name="name" placeholder="name" />
      <input name="password" placeholder="password" type="password" required />
      <button>Register</button>
    </form>`;
  document.getElementById('register-form').addEventListener('submit', async ev=>{
    ev.preventDefault();
    const f = new FormData(ev.target);
    const body = {email: f.get('email'), name: f.get('name'), password: f.get('password')};
    const res = await fetch('/api/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    if(!res.ok){ setAlert('Register failed'); return; }
    setAlert('Registered. Now login.');
    document.getElementById('auth-forms').innerHTML='';
  });
});

document.getElementById('logout').addEventListener('click', (e)=>{
  e.preventDefault();
  setToken(null);
  document.getElementById('logout').style.display='none';
  document.getElementById('show-login').style.display='inline';
  document.getElementById('show-register').style.display='inline';
  document.getElementById('create-post').style.display='none';
  setAlert('Logged out');
});

document.getElementById('post-form').addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  const f = new FormData(ev.target);
  const token = getToken();
  if(!token){ setAlert('Not authenticated'); return; }
  const body = new FormData();
  body.append('title', f.get('title'));
  body.append('body', f.get('body'));
  const res = await fetch('/api/posts', {method:'POST', body: body, headers: { Authorization: 'Bearer ' + token }});
  if(!res.ok){ setAlert('Create post failed'); return; }
  document.getElementById('post-form').reset();
  setAlert('Post created');
  renderPosts();
});

document.getElementById('upload-form').addEventListener('submit', async (ev)=>{
  ev.preventDefault();
  const f = new FormData(ev.target);
  const token = getToken();
  if(!token){ setAlert('Not authenticated'); return; }
  const body = new FormData();
  body.append('file', f.get('file'));
  const res = await fetch('/api/upload', {method:'POST', body: body, headers: { Authorization: 'Bearer ' + token }});
  if(!res.ok){ setAlert('Upload failed'); return; }
  const j = await res.json();
  const u = document.getElementById('uploads');
  const a = document.createElement('a');
  a.href = j.url;
  a.innerText = j.filename;
  a.target = "_blank";
  u.appendChild(a);
  u.appendChild(document.createElement('br'));
});

async function init(){
  await renderPosts();
  // if token present show create UI
  if(getToken()){
    document.getElementById('show-login').style.display='none';
    document.getElementById('show-register').style.display='none';
    document.getElementById('logout').style.display='inline';
    document.getElementById('create-post').style.display='block';
  }
}

init();
</script>
</body>
</html>
""")


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX_HTML.render()


# ---------------------------
# Small admin utility: create initial admin user if not exist
# ---------------------------
def ensure_admin():
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.is_admin == True).first()
        if not admin:
            # create default admin
            a = User(email="admin@example.com", password_hash=hash_password("admin123"), name="Admin", is_admin=True)
            db.add(a)
            db.commit()
            print("Created default admin admin@example.com / admin123")
    finally:
        db.close()


ensure_admin()
