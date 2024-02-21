#!/usr/bin/env python3
"""
Module for interacting with the database.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from user import Base, User


class DB:
    """
    Class for managing database operations.
    """

    def __init__(self) -> None:
        """
        Initializes a new instance of the DB class.
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

    def _get_session(self) -> Session:
        """
        Returns a database session.
        """
        return self._Session()

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Creates a new user in the database.
        Args:
            email: The email of the user.
            hashed_password: The hashed password of the user.
        Returns:
            The newly created User object.
        """
        session = self._get_session()
        user = User(email=email, hashed_password=hashed_password)
        session.add(user)
        session.commit()
        session.close()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        Finds a user in the database based on the provided criteria.
        Args:
            **kwargs: Keyword arguments representing the search criteria.
        Returns:
            The matching User object.
        Raises:
            NoResultFound: If no user is found matching the criteria.
            InvalidRequestError: If an invalid request is made.
        """
        session = self._get_session()
        try:
            user = session.query(User).filter_by(**kwargs).one()
        except NoResultFound:
            session.close()
            raise
        session.close()
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Updates a user's attributes in the database.
        Args:
            user_id: The ID of the user to update.
            **kwargs: Keyword arguments representing the attributes to update.
        Raises:
            ValueError: If the user ID is invalid or an attribute is not found.
        """
        session = self._get_session()
        try:
            user = session.query(User).filter_by(id=user_id).one()
        except NoResultFound:
            session.close()
            raise ValueError("User ID not found.")
        
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
            else:
                session.close()
                raise ValueError(f"Attribute '{key}' not found.")
        
        session.commit()
        session.close()

