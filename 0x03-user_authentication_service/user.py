#!/usr/bin/env python3
"""
Defines the SQLAlchemy model for the 'User' table.
"""

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    """
    Represents a user in the 'users' table.
    """

    __tablename__ = "users"

    id: int = Column(Integer, primary_key=True)
    email: str = Column(String(250), nullable=False)
    hashed_password: str = Column(String(250), nullable=False)
    session_id: str = Column(String(250), nullable=True)
    reset_token: str = Column(String(250), nullable=True)

    def __repr__(self) -> str:
        """
        Returns a string representation of the User.
        """
        return f"<User(id={self.id}, email={self.email})>"

