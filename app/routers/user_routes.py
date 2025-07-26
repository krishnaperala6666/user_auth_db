from fastapi import APIRouter, Depends, HTTPException
from datetime import datetime, timedelta
from jose import jwt
from app.schemas import RegisterRequest, LoginRequest, ChangePasswordRequest, TokenResponse
from app.utils import hash_password, verify_password, create_access_token, calculate_execution_time, is_password_expired
from app.database import user_collection
from app.exceptions import UserAlreadyExistsException, InvalidCredentialsException, PasswordReuseException
from app.logger import logger
from app.auth import get_current_user, blacklisted_tokens, oauth2_scheme
from app.config import FORGOT_PASSWORD_EXPIRY_HOURS, FORGOT_PASSWORD_MAX_REQUESTS, JWT_SECRET_KEY, JWT_ALGORITHM

router = APIRouter()
forget_password_requests = {}

@router.post("/register")
@calculate_execution_time
def register_user(req: RegisterRequest):
    if user_collection.find_one({"username": req.username}):
        logger.warning(f"Duplicate Registration Attempt for {req.username}")
        raise UserAlreadyExistsException()
    hashed_pwd = hash_password(req.password)
    user = {
        "username": req.username,
        "first_name": req.first_name,
        "last_name": req.last_name,
        "dob": req.dob.isoformat(),
        "doj": req.doj.isoformat(),
        "address": req.address,
        "comment": req.comment,
        "active": req.active,
        "password": hashed_pwd,
        "password_history": [hashed_pwd],
        "last_password_change": datetime.utcnow(),
        "failed_attempts": 0
    }
    user_collection.insert_one(user)
    logger.info(f"User Registered: {req.username}")
    return {"message": "User registered successfully"}

@router.post("/login", response_model=TokenResponse)
@calculate_execution_time
def login_user(req: LoginRequest):
    user = user_collection.find_one({"username": req.username})
    if not user or not verify_password(req.password, user["password"]):
        logger.warning(f"Failed login attempt for {req.username}")
        raise InvalidCredentialsException()
    if is_password_expired(user.get("last_password_change", datetime.utcnow())):
        return {"message": "Password expired. Please change your password before login."}
    token = create_access_token({"sub": user["username"]})
    logger.info(f"User Logged in: {req.username}")
    return TokenResponse(access_token=token)

@router.post("/change-password")
def change_password(req: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    if not verify_password(req.old_password, current_user["password"]):
        raise InvalidCredentialsException()
    new_hashed = hash_password(req.new_password)
    if new_hashed in current_user.get("password_history", []):
        raise PasswordReuseException()
    user_collection.update_one(
        {"username": current_user["username"]},
        {"$set": {"password": new_hashed, "last_password_change": datetime.utcnow()},
         "$push": {"password_history": new_hashed}}
    )
    logger.info(f"Password changed for {current_user['username']}")
    return {"message": "Password changed successfully"}

@router.post("/forgot-password")
def forgot_password(username: str):
    user = user_collection.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if forget_password_requests.get(username, 0) >= FORGOT_PASSWORD_MAX_REQUESTS:
        return {"message": "Maximum password reset attempts reached for today"}
    forget_password_requests[username] = forget_password_requests.get(username, 0) + 1
    reset_token = create_access_token(
        {"sub": username, "purpose": "reset_password"},
        expires_delta=timedelta(hours=FORGOT_PASSWORD_EXPIRY_HOURS)
    )
    reset_link = f"http://localhost:8000/reset-password?token={reset_token}"
    logger.info(f"Password Reset link for {username}: {reset_link}")
    return {"reset_link": reset_link}

@router.post("/reset-password")
def reset_password(token: str, new_password: str):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("purpose") != "reset_password":
            raise HTTPException(status_code=400, detail="Invalid token")
        username = payload.get("sub")
        user = user_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
    except:
        raise HTTPException(status_code=400, detail="Token expired or invalid")
    hashed_pwd = hash_password(new_password)
    user_collection.update_one({"username": username}, {
        "$set": {"password": hashed_pwd, "last_password_change": datetime.utcnow()},
        "$push": {"password_history": hashed_pwd}
    })
    return {"message": "Password reset successfully"}

@router.post("/change-username")
def change_username(new_username: str, current_user: dict = Depends(get_current_user)):
    if user_collection.find_one({"username": new_username}):
        raise UserAlreadyExistsException()
    user_collection.update_one({"username": current_user["username"]}, {"$set": {"username": new_username}})
    logger.info(f"Username changed from {current_user['username']} to {new_username}")
    return {"message": "Username updated successfully"}

@router.post("/logout")
def logout_user(token: str = Depends(oauth2_scheme)):
    blacklisted_tokens.add(token)
    logger.info("User Logged out. Token blacklisted.")
    return {"message": "Logged out successfully"}