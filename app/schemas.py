from pydantic import BaseModel, constr
from datetime import date

class RegisterRequest(BaseModel):
    username: str
    first_name: str
    last_name: str
    dob: date
    doj: date
    address: str
    comment: str
    active: bool = True
    password: constr(min_length=8, max_length=20)

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: constr(min_length=8, max_length=20)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"