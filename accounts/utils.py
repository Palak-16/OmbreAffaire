import random
from django.core.mail import send_mail
from django.conf import settings

def generate_otp():
    return str(random.randint(100000, 999999))  # 6-digit OTP

def send_verification_email(email, otp):
    subject = "Your One-Time Password (OTP) for OmbreAffaire"
    message = f"""
    <html>
    <body>
        <p>Hello,</p>
        <p>Your OTP for logging in to <strong>OmbreAffaire</strong> is: <strong>{otp}</strong></p>
        <p>If you didn’t request this, please ignore this email.</p>
        <p>Thanks,<br>OmbreAffaire Team</p>
    </body>
    </html>
    """
    send_mail(subject, "", settings.EMAIL_HOST_USER, [email], html_message=message)