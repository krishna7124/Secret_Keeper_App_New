from database import *
from cryptography.fernet import Fernet
import logging
import spacy
from textblob import TextBlob

# Load the spaCy NLP model
nlp = spacy.load("en_core_web_sm")
# nlp = spacy.load("xx_ent_wiki_sm")


def encrypt_secret(secret, key):
    """Encrypt the secret using the provided key."""
    fernet = Fernet(key)
    encrypted_secret = fernet.encrypt(secret.encode())
    return encrypted_secret


def decrypt_secret(encrypted_secret, key):
    """Decrypt the secret using the provided key."""
    fernet = Fernet(key)
    decrypted_secret = fernet.decrypt(encrypted_secret).decode()
    return decrypted_secret


def analyze_secret(secret):
    """Analyze the secret using SpaCy NLP to extract keywords or named entities."""

    doc = nlp(secret)
    # entities = [(ent.text, ent.label_)for ent in doc.ents]  # Extract named entities
    entities = [(ent.text, ent.label_) for ent in doc.ents if ent.text]

    analysis = TextBlob(secret)
    # Range from -1 (negative) to 1 (positive)
    sentiment_score = analysis.sentiment.polarity

    if sentiment_score > 0:
        sentiment = "Positive 😊"
    elif sentiment_score < 0:
        sentiment = "Negative 😢"
    else:
        sentiment = "Neutral 😐"

    return {
        "entities": entities,
        "sentiment": sentiment,
    }


def add_secret(user_id, secret):
    """Add a secret to the database for the user."""
    conn = create_connection()
    if conn is None:
        return

    secret_key = get_secret_key(user_id)
    if secret_key is None:
        logging.warning("No secret key found for the given user ID.")
        logging.info(f"Generating New Secret Key for user {user_id}")
        store_secret_key(user_id)
        return

    # Analyze the secret with SpaCy NLP
    entities = analyze_secret(secret)
    logging.info(f"Entities found in secret: {entities}")

    encrypted_secret = encrypt_secret(secret, secret_key)
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO secrets (user_id, secret) VALUES (%s, %s)", (user_id, encrypted_secret))
        conn.commit()
        logging.info(f"Secret added for user ID {user_id}.")
    except Exception as e:
        logging.error(f"Error adding secret: {e}")
    finally:
        conn.close()


def view_secrets(user_id):
    """Retrieve secrets for the user."""
    conn = create_connection()
    if conn is None:
        return None

    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, secret FROM secrets WHERE user_id = %s", (user_id,))
        secrets = cursor.fetchall()
        decrypted_secrets = []
        secret_key = get_secret_key(user_id)

        for secret in secrets:
            decrypted_secret = decrypt_secret(secret[1], secret_key)
            decrypted_secrets.append((secret[0], decrypted_secret))

            # Analyze the decrypted secret
            entities = analyze_secret(decrypted_secret)
            # logging.info(f"Entities found in retrieved secret: {entities}")

        return decrypted_secrets
    except Exception as e:
        logging.error(f"Error retrieving secrets: {e}")
    finally:
        conn.close()


def delete_secret(user_id, secret_id):
    """Delete a secret from the database for the user."""
    conn = create_connection()
    if conn is None:
        return

    try:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM secrets WHERE user_id = %s AND id = %s", (user_id, secret_id))
        conn.commit()
        logging.info(f"Secret ID {secret_id} deleted for user ID {user_id}.")
    except Exception as e:
        logging.error(f"Error deleting secret: {e}")
    finally:
        conn.close()
