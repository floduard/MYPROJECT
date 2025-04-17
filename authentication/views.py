from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from .models import *
from django.contrib import messages
from .utils import *
from django.conf import settings
import requests
from .forms import *


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        recaptcha_response = request.POST.get('g-recaptcha-response')

        # Step 1: Validate reCAPTCHA
        recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        recaptcha_data = {
            'secret': settings.RECAPTCHA_PRIVATE_KEY,
            'response': recaptcha_response,
        }
        recaptcha_verify = requests.post(recaptcha_url, data=recaptcha_data)
        recaptcha_result = recaptcha_verify.json()

        if not recaptcha_result.get('success'):
            messages.error(request, "Invalid reCAPTCHA. Please try again.")
            return render(request, 'authentication/login.html', {'recaptcha_site_key': settings.RECAPTCHA_PUBLIC_KEY})

        # Step 2: Authenticate the user
        user = authenticate(request, username=username, password=password)
        if user:
            # Step 3: Check if MFA is enabled
            if user.profile.is_mfa_enabled:
                # Save the user's state in the session for MFA verification
                request.session['pre_mfa_user_id'] = user.id

                # Trigger MFA based on the selected method
                if user.profile.mfa_method == 'email':
                    send_email_otp(user)
                    messages.info(request, "An OTP has been sent to your email.")
                elif user.profile.mfa_method == 'sms':
                    send_sms_otp(user)
                    messages.info(request, "An OTP has been sent to your phone.")
                elif user.profile.mfa_method == 'totp':
                    messages.info(request, "Use your TOTP app to enter the verification code.")

                # Redirect to the OTP verification page
                return redirect('otp_verification')

            # If MFA is not enabled, log the user in directly
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, 'authentication/login.html', {'recaptcha_site_key': settings.RECAPTCHA_PUBLIC_KEY})
def otp_verification(request):
    """
    Handle OTP verification for MFA.
    """
    if request.method == 'POST':
        otp = request.POST.get('otp')
        user_id = request.session.get('pre_mfa_user_id')

        if not user_id:
            messages.error(request, "Session expired. Please log in again.")
            return redirect('login')

        # Retrieve the user
        user = User.objects.get(id=user_id)

        # Validate the OTP based on the selected MFA method
        if user.profile.mfa_method == 'email' or user.profile.mfa_method == 'sms':
            if user.profile.otp == otp:
                # OTP is valid; log the user in
                login(request, user)
                del request.session['pre_mfa_user_id']  # Clear the session
                messages.success(request, "You have been successfully logged in.")
                return redirect('home')
            else:
                messages.error(request, "Invalid OTP. Please try again.")
        elif user.profile.mfa_method == 'totp':
            if validate_totp(user.profile.totp_secret, otp):
                # TOTP is valid; log the user in
                login(request, user)
                del request.session['pre_mfa_user_id']  # Clear the session
                messages.success(request, "You have been successfully logged in.")
                return redirect('home')
            else:
                messages.error(request, "Invalid TOTP code. Please try again.")

    return render(request, 'authentication/otp_verification.html')

@login_required
def home(request):
    return render(request, 'authentication/home.html')

@login_required
def profile(request):
    if request.method == 'POST':
        user = request.user
        user.username = request.POST.get('username', user.username)
        user.email = request.POST.get('email', user.email)
        user.set_password(request.POST.get('password', user.password))
        user.save()
    return render(request, 'authentication/profile.html', {'user': request.user})

@login_required
def setting(request):
    """
    Manage user settings including MFA, email, and phone number.
    """
    if request.method == 'POST':
        action = request.POST.get('action')

        # Enable MFA
        if action == 'enable_mfa':
            method = request.POST.get('mfa_method')
            request.user.profile.mfa_method = method
            request.user.profile.is_mfa_enabled = True

            if method == 'email':
                send_email_otp(request.user)
            elif method == 'sms':
                if not request.user.profile.phone_number:
                    messages.error(request, "Please add your phone number to enable SMS-based MFA.")
                    return redirect('settings')
                send_sms_otp(request.user)
            elif method == 'totp':
                if not request.user.profile.totp_secret:
                    request.user.profile.totp_secret = generate_totp_secret()
                messages.success(request, "Use the following secret key to configure your TOTP app:\n"
                                          f"{request.user.profile.totp_secret}")

            request.user.profile.save()
            messages.success(request, f"MFA enabled using {method}.")
        
        # Disable MFA
        elif action == 'disable_mfa':
            request.user.profile.is_mfa_enabled = False
            request.user.profile.save()
            messages.success(request, "MFA has been disabled.")

        # Update Phone Number
        elif action == 'update_phone_number':
            phone_number = request.POST.get('phone_number')
            request.user.profile.phone_number = phone_number
            request.user.profile.save()
            messages.success(request, "Phone number updated.")

        # Update Email
        elif action == 'update_email':
            new_email = request.POST.get('email')
            request.user.email = new_email
            request.user.save()
            messages.success(request, f"Email updated to {new_email}.")

        # Email Verification
        elif action == 'verify_email':
            send_email_verification(request.user)
            messages.success(request, "A verification email has been sent.")

    return render(request, 'authentication/settings.html', {'user': request.user})

@login_required
def news(request):
    # Example: Hardcoded news articles
    articles = [
        {"title": "Breaking News 1", "content": "Content of breaking news 1."},
        {"title": "Breaking News 2", "content": "Content of breaking news 2."},
    ]
    return render(request, 'authentication/news.html', {'articles': articles})

def logout_view(request):
    logout(request)
    return redirect('login')

def send_email_otp(user):
    otp = generate_otp()
    user.profile.otp = otp
    user.profile.save()
    send_mail(
        'Your OTP Code',
        f'Your OTP code is {otp}',
        'flodouard2000@gmail.com',
        [user.email],
        fail_silently=False,
    )
def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            request.session['reg_data'] = form.cleaned_data
            otp = str(random.randint(100000, 999999))
            request.session['reg_otp'] = otp

            # Send OTP to email
            send_mail(
                'Your OTP Code',
                f'Your registration OTP is: {otp}',
                settings.EMAIL_HOST_USER,
                [form.cleaned_data['email']],
                fail_silently=False,
            )

            return redirect('verify_registration_otp')
    else:
        form = RegisterForm()
    return render(request, 'authentication/register.html', {'form': form})

def verify_registration_otp(request):
    if 'reg_data' not in request.session:
        return redirect('register')

    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['otp'] == request.session.get('reg_otp'):
                data = request.session.get('reg_data')
                user = User.objects.create_user(
                    username=data['username'],
                    email=data['email'],
                    password=data['password']
                )
                login(request, user)
                del request.session['reg_data']
                del request.session['reg_otp']
                messages.success(request, "Registration successful.")
                return redirect('home')
            else:
                messages.error(request, "Invalid OTP. Try again.")
    else:
        form = OTPVerificationForm()
    return render(request, 'authentication/verify_otp.html', {'form': form})

def user_guide_view(request):
    return render(request, 'authentication/user_guide.html')