from sqlalchemy import Column, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship

from app.db.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    security_phrase = Column(String)
    analysis_state = relationship("UserAnalysisState", back_populates="user", uselist=False, cascade="all, delete-orphan")


class UserAnalysisState(Base):
    __tablename__ = "user_analysis_states"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True)
    summary = Column(JSON, nullable=False)
    predictions = Column(JSON, nullable=False, default=list)
    dashboard = Column(JSON, nullable=True)
    assistant_summary = Column(String, nullable=True)
    remediation = Column(JSON, nullable=False, default=list)

    user = relationship("User", back_populates="analysis_state")
