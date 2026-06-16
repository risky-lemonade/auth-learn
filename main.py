from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import jwt

SECRET_KEY = "mysecretkey123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
def create_token(data: dict):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return token

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
def login (user: User):
    conn=sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, password FROM users where username = ?", (user.username, ))
    current_user = cursor.fetchone()

    if current_user is None:
        raise HTTPException(status_code = 401, detail = "user not found")
    hashed = current_user[1]
    if not pwd_context.verify(user.password, hashed):
        raise HTTPException(
            status_code=401,
            detail="Invalid password"
        )

    data = {"sub": current_user[0]}
    token = create_token(data)
    return {"access_token": token}


