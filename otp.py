import os
import random
import smtplib
from email.mime.text import MIMEText
import logging

# Fetch SMTP credentials from Azure environment variables
email_user = os.getenv("email_user")  
email_password = os.getenv("email_password")

# Generate a random OTP
def generate_otp():
    otp = random.randint(100000, 999999)  # 6-digit OTP
    logging.info(f"Generated OTP: {otp}")
    return otp

# Send OTP via email
def send_otp_via_email(recipient_email, otp, purpose):

    if purpose == "login":
        try:
            msg = MIMEText(
                f'''Hi, \n Your OTP for Login verification is: {otp} ''')
            msg['Subject'] = 'Secret Keeper App Login OTP'
            msg['From'] = email_user  # Sender's email
            msg['To'] = recipient_email

            # Gmail SMTP server details
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(email_user, email_password)  # Use App Password
                server.send_message(msg)

            logging.info(f"OTP sent successfully to {recipient_email}")
            return True
        except Exception as e:
            logging.error(f"Failed to send OTP: {e}")
            return False

    elif purpose == "signup":
        try:
            msg = MIMEText(
                f'''Hi, Your OTP for Registration verification is: {otp} ''')
            msg['Subject'] = 'Secret Keeper App Registration OTP'
            msg['From'] = email_user  # Sender's email
            msg['To'] = recipient_email

            # Gmail SMTP server details
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(email_user, email_password)  # Use App Password
                server.send_message(msg)

            logging.info(f"OTP sent successfully to {recipient_email}")
            return True
        except Exception as e:
            logging.error(f"Failed to send OTP: {e}")
            return False

    else:
        logging.error("Registration Failed {e}.")
        return False


# # For Testing OTP Functionality
# # generate_otp()
# test_otp = generate_otp()
# send_otp_via_email('krishnabhatt268@gmail.com', test_otp)

# print(test_otp)

# a = int(input(print("Enter OTP: ")))

# if a == test_otp:
#     print("Otp Entered is correc")
# else:
#     print("Invalid otp")
