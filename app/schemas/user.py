from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str
    security_phrase: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

class PasswordReset(BaseModel):
    username: str
    security_phrase: str
    new_password: str
