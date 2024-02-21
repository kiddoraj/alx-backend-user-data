#!/usr/bin/env python3
"""
Module for authentication and user management.
"""

import bcrypt
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound
from typing import Union

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """
    Hashes a password string using bcrypt.
    
    Args:
        password: The password to hash.
    
    Returns:
        The hashed password.
    """
    password_bytes = password.encode('utf-8')
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generates a UUID and returns its string representation.
    
    Returns:
        The string representation of the generated UUID.
    """
    return str(uuid4())


class Auth:
    """
    Class for authentication and user management.
    """

    def __init__(self) -> None:
        """
        Initializes a new instance of the Auth class.
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> Union[User, None]:
        """
        Registers a new user.

        Args:
            email: The email of the user.
            password: The password of the user.

        Returns:
            The newly created User object if registration is successful, else None.
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            if existing_user:
                return None
        except NoResultFound:
            pass
        
        hashed_password = _hash_password(password)
        return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates a user's login credentials.

        Args:
            email: The email of the user.
            password: The password of the user.

        Returns:
            True if the credentials are valid, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        
        hashed_password = user.hashed_password.encode('utf-8')
        provided_password = password.encode('utf-8')
        return bcrypt.checkpw(provided_password, hashed_password)

    def create_session(self, email: str) -> Union[str, None]:
        """
        Creates a session for the user.

        Args:
            email: The email of the user.

        Returns:
            The session ID if successful, else None.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """
        Retrieves the user associated with the given session ID.

        Args:
            session_id: The session ID of the user.

        Returns:
            The user object if found, else None.
        """
        if not session_id:
            return None
        
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys the session for the user.

        Args:
            user_id: The ID of the user.
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> Union[str, None]:
        """
        Generates a reset password token for the user.

        Args:
            email: The email of the user.

        Returns:
            The reset password token if successful, else None.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, new_password: str) -> None:
        """
        Updates the password for the user using the reset token.

        Args:
            reset_token: The reset password token.
            new_password: The new password for the user.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            return
        
        hashed_password = _hash_password(new_password)
        self._db.update_user(user.id, hashed_password=hashed_password, reset_token=None)

