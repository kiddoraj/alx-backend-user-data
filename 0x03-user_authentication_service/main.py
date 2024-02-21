#!/usr/bin/env python3
"""
Main file for testing user registration, login, and password reset functionality.
"""

import requests

def register_user(email: str, password: str) -> None:
    """
    Register a user with the given email and password.
    
    Args:
        email: The email of the user.
        password: The password of the user.
        
    Raises:
        AssertionError: If the registration fails or the email is already registered.
    """
    resp = requests.post('http://127.0.0.1:5000/users', data={'email': email, 'password': password})
    if resp.status_code == 200:
        assert resp.json() == {"email": email, "message": "user created"}
    else:
        assert resp.status_code == 400
        assert resp.json() == {"message": "email already registered"}

def log_in_wrong_password(email: str, password: str) -> None:
    """
    Attempt to log in with the given wrong credentials.
    
    Args:
        email: The email of the user.
        password: The password of the user.
        
    Raises:
        AssertionError: If login is successful with wrong credentials.
    """
    resp = requests.post('http://127.0.0.1:5000/sessions', data={'email': email, 'password': password})
    assert resp.status_code == 401

def profile_unlogged() -> None:
    """
    Test for accessing profile without being logged in.
    
    Raises:
        AssertionError: If profile access is granted without authentication.
    """
    resp = requests.get('http://127.0.0.1:5000/profile')
    assert resp.status_code == 403

def log_in(email: str, password: str) -> str:
    """
    Log in with the given correct email and password.
    
    Args:
        email: The email of the user.
        password: The password of the user.
        
    Returns:
        The session_id of the user.
        
    Raises:
        AssertionError: If login fails.
    """
    resp = requests.post('http://127.0.0.1:5000/sessions', data={'email': email, 'password': password})
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "logged in"}
    return resp.cookies['session_id']

def profile_logged(session_id: str) -> None:
    """
    Test for accessing profile while logged in.
    
    Args:
        session_id: The session_id of the user.
        
    Raises:
        AssertionError: If profile access is denied.
    """
    cookies = {'session_id': session_id}
    resp = requests.get('http://127.0.0.1:5000/profile', cookies=cookies)
    assert resp.status_code == 200

def log_out(session_id: str) -> None:
    """
    Log out with the given session_id.
    
    Args:
        session_id: The session_id of the user.
        
    Raises:
        AssertionError: If logout fails.
    """
    cookies = {'session_id': session_id}
    resp = requests.delete('http://127.0.0.1:5000/sessions', cookies=cookies)
    if resp.status_code == 302:
        assert resp.url == 'http://127.0.0.1:5000/'
    else:
        assert resp.status_code == 200

def reset_password_token(email: str) -> str:
    """
    Request a password reset token for the given email.
    
    Args:
        email: The email of the user.
        
    Returns:
        The reset_token of the user.
        
    Raises:
        AssertionError: If token retrieval fails.
    """
    resp = requests.post('http://127.0.0.1:5000/reset_password', data={'email': email})
    assert resp.status_code == 200
    return resp.json()['reset_token']

def update_password(email: str, reset_token: str, new_password: str) -> None:
    """
    Update password with the given email, reset_token, and new_password.
    
    Args:
        email: The email of the user.
        reset_token: The reset_token of the user.
        new_password: The new password of the user.
        
    Raises:
        AssertionError: If password update fails.
    """
    data = {'email': email, 'reset_token': reset_token, 'new_password': new_password}
    resp = requests.put('http://127.0.0.1:5000/reset_password', data=data)
    assert resp.status_code == 200
    assert resp.json() == {"email": email, "message": "Password updated"}

if __name__ == "__main__":
    EMAIL = "guillaume@holberton.io"
    PASSWD = "b4l0u"
    NEW_PASSWD = "t4rt1fl3tt3"

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)

