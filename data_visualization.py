import matplotlib.pyplot as plt
import numpy as np
import streamlit as st
import seaborn as sns
import plotly.graph_objects as go
from secret import analyze_secret
from matplotlib.patches import FancyBboxPatch

# Define a mapping of sentiment labels to numeric scores
SENTIMENT_MAP = {
    "Positive 😊": 1.0,
    "Neutral 😐": 0.0,
    "Negative 😢": -1.0
}


def filter_secrets_by_user(secrets, user_id):
    """Filter secrets to only include those belonging to the logged-in user."""
    return [secret for secret in secrets if secret[2] == user_id]  # Assuming secret[2] is the user_id field



def visualize_secret_sentiments(secrets):
    """Visualize sentiment scores and sentiment category counts of the user's secrets."""
    if not secrets:
        st.warning("No secrets available for visualization.")
        return

    # Analyze the sentiment of each secret
    sentiments_raw = [analyze_secret(secret[1])['sentiment'] for secret in secrets]
    sentiments = [SENTIMENT_MAP.get(sent, 0.0) for sent in sentiments_raw]

    # Prepare data for visualization
    secret_ids = [secret[0] for secret in secrets]
    y_pos = np.arange(len(secret_ids))

    # Count occurrences of each sentiment category
    sentiment_categories = {"Positive 😊": 0, "Neutral 😐": 0, "Negative 😢": 0}
    for sent in sentiments_raw:
        if sent in sentiment_categories:
            sentiment_categories[sent] += 1

    # Set color palette based on sentiment score
    colors = ['#a2d729' if s == 1 else '#f4d35e' if s == 0 else '#ee6055' for s in sentiments]

    # Interactive selection for filtering
    sentiment_filter = st.selectbox("Select Sentiment to Filter", options=["All", "Positive 😊", "Neutral 😐", "Negative 😢"])

    # Filter secrets based on sentiment selection
    if sentiment_filter != "All":
        filtered_secrets = [secrets[i] for i in range(len(secrets)) if sentiments_raw[i] == sentiment_filter]
    else:
        filtered_secrets = secrets

    if not filtered_secrets:
        st.warning("No secrets match the selected sentiment.")
        return

    # Prepare data for filtered visualization
    filtered_sentiments_raw = [analyze_secret(secret[1])['sentiment'] for secret in filtered_secrets]
    filtered_sentiments = [SENTIMENT_MAP.get(sent, 0.0) for sent in filtered_sentiments_raw]
    filtered_secret_ids = [secret[0] for secret in filtered_secrets]
    filtered_y_pos = np.arange(len(filtered_secret_ids))

    # Create subplots
    fig, axes = plt.subplots(1, 2, figsize=(12, 6), gridspec_kw={'width_ratios': [2, 1]})

    # First graph: Sentiment Scores (Bar Graph)
    ax1 = axes[0]
    ax1.barh(filtered_y_pos, filtered_sentiments, align='center', color=colors, edgecolor='black')
    ax1.set_yticks(filtered_y_pos)
    ax1.set_yticklabels([f"Secret ID: {id_}" for id_ in filtered_secret_ids], fontsize=10)
    ax1.set_xlabel('Sentiment Score', fontsize=12)
    ax1.set_title('Sentiment Scores of Your Secrets', fontsize=14, fontweight='bold')
    ax1.grid(True, linestyle='--', alpha=0.6)

    # Second graph: Sentiment Categories Count (Bar Graph)
    ax2 = axes[1]
    category_counts = [sentiment_categories.get(sentiment, 0) for sentiment in ["Positive 😊", "Neutral 😐", "Negative 😢"]]
    ax2.barh(["Positive 😊", "Neutral 😐", "Negative 😢"], category_counts, color=['#a2d729', '#f4d35e', '#ee6055'], edgecolor='black')
    ax2.set_xlabel('Count', fontsize=12)
    ax2.set_title('Sentiment Category Counts', fontsize=14, fontweight='bold')
    ax2.grid(True, linestyle='--', alpha=0.6)

    # Adjust layout for a cleaner look
    plt.tight_layout()

    # Display the plots in Streamlit
    st.pyplot(fig)