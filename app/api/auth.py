from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import timedelta
from jose import JWTError, jwt

from app.db.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin, Token, PasswordChange, PasswordReset
from app.core.security import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

@router.post("/signup", response_model=Token)
def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    username = user_data.username.strip().lower()
    db_user = db.query(User).filter(User.username == username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        username=username,
        hashed_password=hashed_password,
        security_phrase=user_data.security_phrase.strip()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    access_token_expires = timedelta(minutes=60*24)
    access_token = create_access_token(
        data={"sub": new_user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/login", response_model=Token)
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    username = user_data.username.strip().lower()
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=60*24)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/change-password")
def change_password(pass_data: PasswordChange, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(pass_data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid old password")
    current_user.hashed_password = get_password_hash(pass_data.new_password)
    db.commit()
    return {"message": "Password updated successfully"}

@router.post("/reset-password")
def reset_password(reset_data: PasswordReset, db: Session = Depends(get_db)):
    username = reset_data.username.strip().lower()
    security_phrase = reset_data.security_phrase.strip()
    user = db.query(User).filter(User.username == username).first()
    if not user or user.security_phrase.strip() != security_phrase:
        raise HTTPException(status_code=400, detail="Invalid username or security phrase")
    user.hashed_password = get_password_hash(reset_data.new_password)
    db.commit()
    return {"message": "Password reset successfully"}

@router.post("/logout")
def logout(current_user: User = Depends(get_current_user)):
    # JWT is stateless, so "logout" is mostly handled client-side by deleting the token.
    # This endpoint is provided for client convenience and potential future token blocklisting.
    return {"message": "Successfully logged out"}
