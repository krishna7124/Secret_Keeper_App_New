import speech_recognition as sr
import streamlit as st
import logging



def recognize_speech_from_mic():
    """Capture secret using speech recognition."""
    recognizer = sr.Recognizer()
    mic = sr.Microphone()

    with mic as source:
        st.info(" 🎤 Say your secret...")
        recognizer.adjust_for_ambient_noise(source)
        audio = recognizer.listen(source)

    try:
        secret = recognizer.recognize_google(audio)
        logging.info(f"You said: {secret}")
        return secret
    except sr.UnknownValueError:
        st.error(" 🚫 Sorry, I could not understand the audio.")
        return None
    except sr.RequestError as e:
        st.error(
            f"Could not request results from Google Speech Recognition service; {e}")
        return None
