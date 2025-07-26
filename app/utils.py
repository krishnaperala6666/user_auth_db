from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt
from app.config import JWT_SECRET_KEY, JWT_ALGORITHM, JWT_ACCESS_TOKEN_EXPIRE_MINUTES, PASSWORD_EXPIRY_DAYS

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def calculate_execution_time(func):
    from time import time
    def wrapper(*args, **kwargs):
        start = time()
        result = func(*args, **kwargs)
        execution_time = (time() - start) * 1000
        print(f"Execution Time : {execution_time:.2f} ms")
        return result
    return wrapper

def is_password_expired(last_password_change: datetime) -> bool:
    return (datetime.utcnow() - last_password_change).days >= PASSWORD_EXPIRY_DAYS