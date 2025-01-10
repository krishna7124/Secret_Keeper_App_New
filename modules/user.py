import hashlib
from database import create_connection
import re
import logging


def hash_password(password):
    """Hash the password for secure storage."""
    return hashlib.sha256(password.encode()).hexdigest()


def is_username_available(username):
    """Check if the username is available."""
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        count = cursor.fetchone()[0]
        return count == 0  # True if username is available, False otherwise
    return False  # Assume not available if connection fails


def register_user(username, password, first_name, last_name, age, email, biometric_data):
    """Register a new user in the database."""
    conn = create_connection()
    if conn is None:
        logging.error("Database connection failed.")
        return False  # Indicate failure to the caller

    hashed_password = hash_password(password)

    try:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO users (username, password, first_name, last_name, age, email, biometric_data)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (username, hashed_password, first_name, last_name, age, email, biometric_data))

        # Check if the user was inserted successfully
        if cursor.rowcount > 0:
            conn.commit()  # Only commit if the insert was successful
            logging.info(f"User '{username}' registered successfully.")
            return True  # Indicate success to the caller
        else:
            logging.warning(
                f"User '{username}' registration failed: No rows inserted.")
            return False  # Indicate failure

    except Exception as e:
        logging.error(f"Error registering user '{username}': {e}")
        return False  # Indicate failure

    finally:
        conn.close()  # Ensure the connection is closed


def login_user(username, password):
    """Authenticate user login."""
    conn = create_connection()
    if conn is None:
        return False

    hashed_password = hash_password(password)

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = %s AND password = %s", (username, hashed_password))
        user = cursor.fetchone()
        return user is not None  # Return True if user exists
    except Exception as e:
        logging.error(f"Error logging in user: {e}")
    finally:
        conn.close()

    return False


def delete_user_account(user_id):
    """Delete a user account from the database."""
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        try:
            # Delete user secrets associated with the user ID
            cursor.execute(
                "DELETE FROM secrets WHERE user_id = %s", (user_id,))
            # Delete the user account
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            logging.info(
                f"User account with ID {user_id} deleted successfully.")
            return True
        except Exception as e:
            logging.error(f"Error deleting user account: {e}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            conn.close()
    return False


def get_email_id(username):
    """Get user ID from the database based on username."""
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT email FROM users WHERE username = %s", (username,))
        user_email = cursor.fetchone()
        if user_email:
            return user_email[0]
    return None


def get_user_id(username):
    """Get user ID from the database based on username."""
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user_id = cursor.fetchone()
        if user_id:
            return user_id[0]
    return None


def is_valid_email(email):
    """Check if the provided email has a valid format."""
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None
