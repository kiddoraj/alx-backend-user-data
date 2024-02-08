#!/usr/bin/env python3
"""
Defines functions for hashing passwords and validating them.
"""

import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Returns a hashed version of the input password.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password.
    """
    encoded_password = password.encode()
    hashed = hashpw(encoded_password, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Checks whether a password matches its hashed version.

    Args:
        hashed_password (bytes): The hashed password to compare against.
        password (str): The password in plain text.

    Returns:
        bool: True if the password matches the hashed version, False otherwise.
    """
    encoded_password = password.encode()
    return bcrypt.checkpw(encoded_password, hashed_password)
