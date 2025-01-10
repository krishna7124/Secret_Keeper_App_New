import streamlit as st
import logging
import time

def initialize_session():
    """Initialize the session state for user login."""
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = None
    if 'registration_successful' not in st.session_state:
        st.session_state.registration_successful = False
    if 'show_login_page' not in st.session_state:
        st.session_state.show_login_page = False

def logout_user():
    """Log out the user and reset session state."""
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.user_id = None
    st.session_state.last_activity = None
    st.session_state.registration_successful = False
    st.session_state.show_login_page = False
    st.success("You have been logged out.")

# Set the timeout period in seconds
SESSION_TIMEOUT = 600  # 10 minutes

def check_session_timeout():
    """Check if the session has timed out due to inactivity."""
    # Initialize last_activity if not already set
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = time.time()

    if st.session_state.last_activity:
        elapsed_time = time.time() - st.session_state.last_activity
        if elapsed_time > SESSION_TIMEOUT:
            st.warning("Your session has timed out due to inactivity.")
            logout_user()  # Call the logout function
            logging.info("User session timed out.")

    # Update last activity time
    st.session_state.last_activity = time.time()