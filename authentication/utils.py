import random
import pyotp
from twilio.rest import Client

def generate_otp():
    """
    Generate a 6-digit numeric OTP.
    """
    return str(random.randint(100000, 999999))

def send_email_otp(user):
    """
    Send an OTP to the user's email for MFA.
    """
    otp = generate_otp()
    user.profile.otp = otp
    user.profile.save()
    send_mail(
        'Your OTP Code',
        f'Your OTP code is {otp}',
        'your-email@example.com',
        [user.email],
        fail_silently=False,
    )

def send_sms_otp(user):
    """
    Send an OTP to the user's phone number via SMS for MFA.
    """
    otp = generate_otp()
    user.profile.otp = otp
    user.profile.save()

    # Twilio SMS API integration
    account_sid = 'your_twilio_account_sid'
    auth_token = 'your_twilio_auth_token'
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=f'Your OTP code is {otp}',
        from_='+1234567890',  # Twilio phone number
        to=user.profile.phone_number,
    )
    return message.sid

def generate_totp_secret():
    """
    Generate a TOTP secret key for the user.
    """
    return pyotp.random_base32()

def validate_totp(totp_secret, code):
    """
    Validate a TOTP code using the provided secret.
    """
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(code)