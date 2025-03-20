import streamlit as st
from database import setup_database, get_secret_key, store_secret_key, create_connection
from user import hash_password, register_user, login_user, delete_user_account, is_username_available, get_user_id, get_email_id, is_valid_email
from secret import add_secret, view_secrets, delete_secret, analyze_secret
from biometric import biometric_verification, capture_and_store_biometric_data
from session import initialize_session, logout_user, check_session_timeout
from data_visualization import visualize_secret_sentiments
from SpeechRecognizer import recognize_speech_from_mic
from otp import generate_otp, send_otp_via_email
import logging
import re
import os

port = int(os.environ.get("PORT", 8000))
app.run(host="0.0.0.0", port=port, debug=True)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

st.set_page_config(page_icon="🔐",page_title="Secret Keeper App", layout="wide")

st.markdown("""
    <style>
        .reportview-container {
            margin-top: -2em;
        }
        #MainMenu {visibility: hidden;}
        .stDeployButton {display:none;}
        footer {visibility: hidden;}
        #stDecoration {display:none;}
    </style>
""", unsafe_allow_html=True)


def is_strong_password(password):
    """Check if the password meets strength requirements."""
    if len(password) < 12:
        logging.warning("Password is too short.")
        return False
    if not re.search(r'[A-Z]', password):
        logging.warning("Password does not contain an uppercase letter.")
        return False
    if not re.search(r'[a-z]', password):
        logging.warning("Password does not contain a lowercase letter.")
        return False
    if not re.search(r'[0-9]', password):
        logging.warning("Password does not contain a number.")
        return False
    return True


def login_user_interface():
    """Handle the login interface and process with OTP and biometric verification."""
    # Check if the user is already logged in
    if 'logged_in' in st.session_state and st.session_state['logged_in']:
        st.success(f"✅ You are logged in as {st.session_state['username']}")
        if st.button("Logout"):
            logout_user()
        return

    st.subheader("🔐 Login to Your Account")
    st.markdown(" 📋 Please enter your credentials to login.")
    username = st.text_input("Username", placeholder="Enter your username")
    password = st.text_input("Password", type='password',
                             placeholder="Enter your password")

    # Step 1: Verify user credentials (Username/Password)
    if st.button("Login"):
        if username.strip() == "":
            st.error("Username cannot be empty.")
        elif password.strip() == "":
            st.error("Password cannot be empty.")
        else:
            # If login credentials are correct, proceed to OTP verification
            if login_user(username, password):
                st.session_state['otp_sent'] = True
                st.session_state['username'] = username
                otp = generate_otp()
                st.session_state['otp'] = otp
                email = get_email_id(username)
                send_otp_via_email(email, otp, purpose="login")
                st.success(f"📧 OTP sent to {email}. Please check your inbox.")
            else:
                st.error("Invalid username or password.")

    # Step 2: OTP Verification
    if 'otp_sent' in st.session_state and st.session_state['otp_sent']:
        user_otp = st.text_input(
            "Enter OTP sent to your email", type="password")

        if st.button("Verify OTP"):
            if user_otp == str(st.session_state['otp']):
                st.session_state['otp_verified'] = True
                st.success("✅ OTP verified successfully!")
            else:
                st.error("Invalid OTP. Please try again.")

    # Step 3: Biometric Verification via Browser Camera
    if 'otp_verified' in st.session_state and st.session_state['otp_verified']:
        st.info("📷 Capture your biometric data to login:")
        enable = st.checkbox("Enable camera")
        captured_image = st.camera_input("Take a picture", disabled=not enable)

        if captured_image is not None and st.button("Verify Biometric Data"):
            if biometric_verification(st.session_state['username'], captured_image):
                st.session_state.logged_in = True
                st.session_state.user_id = get_user_id(
                    st.session_state['username'])
                st.success("✅ Login successful!")
                st.rerun()  # Refresh the app state
            else:
                st.error("⚠️ Biometric data capture failed. Please try again.")


def register_user_interface():
    """Handle the user registration process with OTP verification."""
    st.subheader("📝 Register a New Account")
    st.markdown(" 🛠️ Create a new account with your details.")
    username = st.text_input("Username", placeholder="Choose a username")
    password = st.text_input("Password", type='password',
                             placeholder="Set a strong password (at least 12 chars, 1 uppercase, 1 number)")
    confirm_password = st.text_input(
        "Confirm Password", type='password', placeholder="Re-enter your password")
    first_name = st.text_input(
        "First Name", placeholder="Enter your first name")
    last_name = st.text_input("Last Name", placeholder="Enter your last name")
    age = st.number_input("Age", min_value=0, max_value=120, step=1)
    email = st.text_input("Email", placeholder="Enter your email address")

    # Step 1: Registration input validation and OTP generation
    if st.button("Register"):
        if username.strip() == "" or password.strip() == "" or password.strip() == "" or confirm_password.strip() == "" or last_name.strip() == "" or email.strip() == "":
            st.error("❌ All fields must be filled.")
            logging.warning(
                "Registration attempt failed: All fields must be filled.")
        elif password != confirm_password:
            st.error("❌ Passwords do not match.")
            logging.warning(
                "Registration attempt failed: Passwords do not match.")
        elif not is_strong_password(password.strip()):
            st.error(
                "Password must be at least 12 characters long, contain an uppercase letter, and a number.")
            logging.warning("Registration attempt failed: Weak password.")
        elif not is_valid_email(email.strip()):
            st.error("❌ Invalid email format.")
            logging.warning(
                f"Registration attempt failed: Invalid email '{email}'.")
        else:
            # Check if the username is already in use
            if not is_username_available(username):
                st.error("Registration failed: Username already in use.")
                logging.warning(f"Registration attempt failed: Username '{
                                username}' already in use.")
            else:
                otp = generate_otp()
                st.session_state['otp'] = otp
                st.session_state['registration_data'] = {
                    'username': username,
                    'password': password,
                    'first_name': first_name,
                    'last_name': last_name,
                    'age': age,
                    'email': email
                }
                try:
                    send_otp_via_email(email, otp, purpose="signup")
                    st.success(f"OTP sent to {
                               email}. Please check your inbox.")
                    logging.info(f"OTP sent to {email} for user '{username}'.")
                except Exception as e:
                    st.error("Failed to send OTP. Please try again.")
                    logging.error(f"Error sending OTP to {email}: {e}")

    # Step 2: OTP Verification
    if 'otp' in st.session_state:
        user_otp = st.text_input(
            "Enter OTP sent to your email", type="password")
        if st.button("Verify OTP"):
            if user_otp == str(st.session_state['otp']):
                st.session_state['otp_verified'] = True
                st.success("✅ OTP verified successfully!")
                logging.info(f"OTP verified for user '{
                             st.session_state['registration_data']['username']}'.")
            else:
                st.error("Invalid OTP. Please try again.")
                logging.warning(f"Invalid OTP entered for user '{
                                st.session_state['registration_data']['username']}'.")

    # Step 3: Biometric Data Capture via Browser and Final Registration
    if 'otp_verified' in st.session_state and st.session_state['otp_verified']:
        st.info("📷 Capture your biometric data for registration:")
        enable = st.checkbox("Enable camera")
        captured_image = st.camera_input("Take a picture", disabled=not enable)
        # captured_image = st.camera_input("Take a picture")

        if captured_image is not None and st.button("Capture Biometric Data"):
            try:
                # Perform biometric data storage with the captured image
                biometric_data = capture_and_store_biometric_data(
                    st.session_state['registration_data']['username'], captured_image)
                if biometric_data is not None:
                    # Proceed with registration after biometric data capture
                    registration_result = register_user(
                        **st.session_state['registration_data'], biometric_data=biometric_data)
                    if registration_result:
                        user_id = get_user_id(
                            st.session_state['registration_data']['username'])
                        if user_id:  # Ensure user_id is valid
                            store_secret_key(user_id)
                            st.success(
                                "🎉 Registration successful! Please log in.")
                            st.session_state.registration_successful = True
                            st.rerun()  # Rerun to show the success page

                            logging.info(
                                f"User '{username}' registered successfully with user ID '{user_id}'.")
                        else:
                            st.error("User ID not found after registration.")
                            logging.error(
                                "User ID not found after registration.")
                    else:
                        st.error("Registration failed. Please try again.")
                        logging.error(
                            f"Registration failed for user '{username}'.")
                else:
                    st.warning(
                        "⚠️ Biometric data capture failed. Registration aborted.")
                    logging.warning(
                        "Biometric data capture failed for user '{username}'.")
            except Exception as e:
                logging.error(
                    f"Error '{e}' occurred while capturing biometric data or registering user.")
                st.error(
                    "An error occurred during registration. Please try again.")
    if st.session_state.get('registration_successful'):
        registration_success_page()


def registration_success_page():
    """
    Displays a success message after registration and a button to navigate to the login page.
    """
    st.title("🎉 Registration Successful!")
    st.success("You have successfully registered! Please log in to continue.")

    # Add a button to navigate to the login page
    if st.button("Go to Login Page"):
        # Set session state to show login form after registration
        st.session_state.show_login_page = True
        st.rerun()


def manage_secrets_interface():
    """Handle secret management actions for logged-in users."""
    if 'logged_in' not in st.session_state or not st.session_state['logged_in']:
        st.warning("You need to be logged in to manage secrets.")
        return

    st.subheader("🔒 Secret Management")
    st.markdown("Manage your secrets securely.")

    secret_choice = st.selectbox("👉 Select an Action", [
        "➕ Add a Secret", "🎤 Add a Secret Using Speech", "👁️ View Secrets", "🗑️ Delete a Secret"
    ])

    if secret_choice == "➕ Add a Secret":
        secret = st.text_area("Enter your secret:",
                              placeholder="Type your secret here...")
        if st.button("Add Secret"):
            if secret:
                add_secret(st.session_state.user_id, secret)
                st.success("✅ Secret added successfully!")

                # Analyze and display entities
                entities = analyze_secret(secret)
                display_nlp_analysis(entities)
            else:
                st.error("❌ Secret cannot be empty.")

    elif secret_choice == "🎤 Add a Secret Using Speech":
        if st.button("Speak Secret"):
            secret = recognize_speech_from_mic()
            if secret:
                add_secret(st.session_state.user_id, secret)
                st.success("🎙️ Secret added successfully from voice input!")
                entities = analyze_secret(secret)
                display_nlp_analysis(entities)
            else:
                st.error("❌ No speech detected. Please try again.")

    elif secret_choice == "👁️ View Secrets":
        # Fetch secrets for the logged-in user
        secrets = view_secrets(st.session_state.user_id)
        if secrets:
            for secret in secrets:
                with st.expander(f"🔐 Secret ID: {secret[0]}, **Secret:** {secret[1]} "):
                    # Display secret details and analysis
                    sentiment = analyze_secret(secret[1])
                    entities = analyze_secret(secret[1])
                    display_nlp_analysis(entities)

            # Visualize secret sentiments for the logged-in user
            visualize_secret_sentiments(secrets)
        else:
            st.warning("🗝️ No secrets found.")

    elif secret_choice == "🗑️ Delete a Secret":
        secret_id = st.number_input(
            "❗ Enter Secret ID to delete:", min_value=1)
        if st.button("Delete Secret"):
            delete_secret(st.session_state.user_id, secret_id)
            st.success(f"🗑️ Secret with ID {secret_id} deleted.")
            st.rerun()  # Refresh the app state


def display_nlp_analysis(result):
    """Display the results of NLP analysis in Streamlit."""
    entities = result["entities"]
    sentiment = result["sentiment"]

    # Display sentiment
    st.write("📊 **Sentiment Analysis:**")
    st.write(f"- Sentiment: {sentiment}")

    # Display entities
    st.write("📊 **Entities received for analysis:**")

    if entities:  # Check if there are any entities
        st.write("Entities:")
        for entity in entities:
            st.write(f"- **Entity:** {entity[0]} | **Type:** {entity[1]}")
    else:
        st.write("- No entities found.")


def logout_user():
    """Handle user logout process by resetting session state."""
    st.session_state['logged_in'] = False
    st.session_state['username'] = None
    st.session_state['user_id'] = None
    st.session_state['otp_sent'] = False
    st.session_state['otp_verified'] = False
    st.success("👋 Logged out successfully.")
    st.rerun()  # Refresh the app state
    logging.info("User logged out.")


def manage_account_interface():
    """Handle user account management (update name, email, and password)."""
    st.subheader("👤 Manage Your Account")
    st.markdown(" 📝 Update your account information below:")

    # Fetch current user data
    conn = create_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, first_name, last_name, email FROM users WHERE id = %s",
                       (st.session_state.user_id,))
        user_data = cursor.fetchone()

    st.markdown(f"**Username:** {user_data[0]}")  # Display the username
    # Input fields for user information
    first_name = st.text_input("First Name", value=user_data[1])
    last_name = st.text_input("Last Name", value=user_data[2])
    email = st.text_input("Email", value=user_data[3])

    # Input fields for password update
    current_password = st.text_input(
        "Current Password", type="password", placeholder="Enter your current password")
    new_password = st.text_input("New Password", type="password",
                                 placeholder="Leave blank if you don't want to change it")
    confirm_new_password = st.text_input(
        "Confirm New Password", type="password", placeholder="Confirm new password")

    # Update account information
    if st.button("🔄 Update Account"):
        if first_name.strip() == "" or last_name.strip() == "" or email.strip() == "":
            st.error("All fields are required.")
        else:
            # Verify the current password
            cursor.execute("SELECT password FROM users WHERE id = %s",
                           (st.session_state.user_id,))
            stored_password = cursor.fetchone()[0]

            if not hash_password(current_password) == stored_password:
                st.error("The current password is incorrect.")
            else:
                # Validate new password if provided
                if new_password:
                    if new_password != confirm_new_password:
                        st.error("New password and confirmation do not match.")
                    elif not is_strong_password(new_password):
                        st.error(
                            "Password must be at least 8 characters long, with uppercase letters and numbers.")
                    else:
                        hashed_password = hash_password(new_password)
                        cursor.execute("UPDATE users SET password = %s WHERE id = %s",
                                       (hashed_password, st.session_state.user_id))

                # Update the rest of the account information
                cursor.execute("""
                    UPDATE users SET first_name = %s, last_name = %s, email = %s WHERE id = %s
                """, (first_name, last_name, email, st.session_state.user_id))

                conn.commit()
                st.success("✅ Account updated successfully!")
                st.rerun()
                logging.info(
                    f"User {st.session_state.username}'s account updated.")

    # New feature: Delete Account
    delete_account = st.button("🚫 Delete Account")

    if delete_account:
        if "delete_confirm" not in st.session_state:
            st.session_state.delete_confirm = False

        if st.session_state.delete_confirm:
            if delete_user_account(st.session_state.user_id):
                st.success("Your account has been deleted successfully.")
                logout_user()  # Log out the user after deletion
            else:
                st.error("Error deleting your account. Please try again.")
        else:
            st.session_state.delete_confirm = True
            if current_password.strip() == "":
                st.error("Password cannot be empty.")
            st.warning(
                "Are you sure you want to delete your account? This action cannot be undone.")
            confirm_delete = st.button("Yes, delete my account")
            cancel_delete = st.button("Cancel")

            if confirm_delete:
                # Proceed with deletion if confirmed
                if delete_user_account(st.session_state.user_id):
                    st.success("Your account has been deleted successfully.")
                    logout_user()
                else:
                    st.error("Error deleting your account. Please try again.")

            if cancel_delete:
                st.session_state.delete_confirm = False  # Reset confirmation status


def home_page():
    """Display the home page content. 🏡"""
    st.title("🏡 Welcome to the Secret Keeper App!")
    st.markdown("""
        Welcome to the **Secret Keeper App**, your secure solution for managing and storing secrets. 
        Our app provides biometric verification, secure password generation, and OTP verification for 
        a safe and user-friendly experience. 

        🌟 **Features:**
        - Biometric Login and Registration
        - Secure Secret Management
        - Strong Password Generation
        - Easy User Management

        Start your journey towards better security today! Please log in or register to get started.
    """)


def main():
    """Main function to run the app."""
    setup_database()
    initialize_session()
    st.title(" 🚀 Secret Keeper App")
    st.sidebar.title(" 📜 Menu")

    # Menu options depending on login status
    if st.session_state.logged_in:

        # Display the username
        st.sidebar.markdown("### 🌟 Welcome to Secret Keeper!")
        st.sidebar.markdown(f"**Hello, {st.session_state.username}!** 😊")
        menu = ["🔒 Manage Secrets", "👤 Manage Account", "📤 Logout"]

    else:
        menu = ["🏠 Home", "🔐 Login", "📝 Register"]

    choice = st.sidebar.selectbox("👉 Choose Action to Continue! ", menu)

    if choice == "🔐 Login":
        login_user_interface()

    elif choice == "📝 Register":
        register_user_interface()

    elif choice == "🏠 Home":
        home_page()
    elif choice == "🔒 Manage Secrets":
        if st.session_state.logged_in:
            manage_secrets_interface()
        else:
            st.warning("Please login first to manage your secrets.")
    elif choice == "👤 Manage Account":
        if st.session_state.logged_in:
            manage_account_interface()
        else:
            st.warning("Please login first to manage your account.")
    elif choice == "📤 Logout":
        logout_user()

    # Check for session timeout (if any session management logic is implemented)
    check_session_timeout()


if __name__ == '__main__':
    main()
