from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import sqlite3
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
def create_token(data: dict):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return token

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute(" CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)")
conn.commit()
conn.close()

class User(BaseModel):
    username: str
    password: str

@app.post("/register/")
def register(user: User):
    conn = sqlite3.connect("users.db")  
    cursor = conn.cursor()

    hashed = pwd_context.hash(user.password)
    cursor.execute("INSERT INTO users (username, password)  VALUES(?,?)", (user.username, hashed, ))  
    conn.commit()
    conn.close()
    return {"message": "User registered successfully", "username": user.username}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM users WHERE username = ?", (form_data.username,))
    current_user = cursor.fetchone()
    if current_user is None:
        raise HTTPException(status_code=401, detail="User not found")
    hashed = current_user[1]
    if not pwd_context.verify(form_data.password, hashed):
        raise HTTPException(status_code=401, detail="Invalid password")
    data = {"sub": current_user[0]}
    token = create_token(data)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def get_me(current_user: str = Depends(get_current_user)):
    return {"username": current_user}


