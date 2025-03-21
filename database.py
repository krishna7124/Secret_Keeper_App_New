import os
import mysql.connector
from mysql.connector import Error
from cryptography.fernet import Fernet
import logging
import base64

# Azure MySQL database configuration (from environment variables)
db_config = {
    "host": os.getenv("AZURE_MYSQL_HOST"),
    "database": os.getenv("AZURE_MYSQL_NAME"),
    "user": os.getenv("AZURE_MYSQL_USER"),
    "password": os.getenv("AZURE_MYSQL_PASSWORD"),
}

def create_connection():
    """Create a database connection to Azure MySQL (without SSL)."""
    try:
        conn = mysql.connector.connect(
            user=db_config["user"],
            password=db_config["password"],
            host=db_config["host"],
            port=3306,
            database=db_config["database"]
        )
        if conn.is_connected():
            logging.info("Connected to MySQL database (Azure).")
            return conn
    except Error as e:
        logging.error(f"Database connection error: {e}")
    return None

def setup_database():
    """Set up the database and create required tables if they do not exist."""
    conn = create_connection()
    if conn is None:
        logging.error("Database connection failed. Exiting setup.")
        return

    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        age INT,
        email VARCHAR(255),
        biometric_data BLOB
    )
    """)

    # Create secrets table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS secrets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        secret TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # Create secret_keys table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS secret_keys (
        user_id INT PRIMARY KEY,
        secret_key BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    # Create secret_tags table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS secret_tags (
        secret_id INT,
        tags VARCHAR(255),
        FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
    )
    """)

    conn.commit()
    logging.info("Database setup complete.")
    cursor.close()
    conn.close()

def get_secret_key(user_id):
    """Retrieve the secret key for a user."""
    conn = create_connection()
    if conn is None:
        return None

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT secret_key FROM secret_keys WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        if result:
            return base64.b64decode(result[0])  # Decode base64 stored key
    except Error as e:
        logging.error(f"Error retrieving secret key: {e}")
    finally:
        conn.close()
    
    return None

def generate_secret_key():
    """Generate a new secret key using Fernet encryption."""
    return Fernet.generate_key()

def store_secret_key(user_id):
    """Store a generated secret key for a user in the database."""
    conn = create_connection()
    if conn is None:
        logging.error("Database connection failed. Secret key storage aborted.")
        return

    secret_key = base64.b64encode(generate_secret_key()).decode('utf-8')  # Encode before storing

    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO secret_keys (user_id, secret_key) VALUES (%s, %s)", (user_id, secret_key))
        conn.commit()
        logging.info("Secret key stored successfully.")
    except Error as e:
        logging.error(f"Error storing secret key: {e}")
    finally:
        cursor.close()
        conn.close()
