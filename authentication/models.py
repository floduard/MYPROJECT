from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    MFA_METHODS = [
        ('email', 'Email'),
        ('sms', 'SMS'),
        ('totp', 'TOTP'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, blank=True, null=True)
    is_mfa_enabled = models.BooleanField(default=False)
    mfa_method = models.CharField(max_length=10, choices=MFA_METHODS, default='email')  # Preferred MFA method
    phone_number = models.CharField(max_length=15, blank=True, null=True)  # For SMS-based OTP
    totp_secret = models.CharField(max_length=32, blank=True, null=True)  # For TOTP

    def __str__(self):
        return self.user.username