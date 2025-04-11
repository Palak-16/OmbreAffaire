from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
import json
from .models import CustomUser
from .utils import generate_otp, send_verification_email
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse
from django.urls import reverse
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

def send_reset_link(request):
    print("Received request at /send-reset-link/")  # Debugging
    if request.method == "POST":
        email = request.POST.get("email")
        print(f"Received password reset request for: {email}")  # Debugging

        try:
            user = CustomUser.objects.get(email=email)
            print(f"User found: {user.email}")  # Debugging
        except CustomUser.DoesNotExist:
            print("No user found with this email.")  # Debugging
            return JsonResponse({"error": "No account found with this email."}, status=400)

        # Generate Password Reset Token
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_url = request.build_absolute_uri(reverse("reset_password", kwargs={"uidb64": uidb64, "token": token}))

        # Debugging
        print(f"Generated Reset URL: {reset_url}")

        # Send Email
        subject = "Reset Your Password - OmbreAffaire"
        message = f"""
        <html>
        <body>
            <p>Hello {user.email},</p>
            <p>Click the link below to reset your password:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
            <p>If you did not request this, please ignore this email.</p>
            <p>Thanks,<br>The OmbreAffaire Team</p>
        </body>
        </html>
        """
        send_mail(subject, "", settings.EMAIL_HOST_USER, [email], html_message=message)
        
        print("Email sent successfully!")  # Debugging
        return JsonResponse({"message": "A password reset link has been sent to your email."})

    return JsonResponse({"error": "Invalid request"}, status=400)


@csrf_exempt
def send_otp(request):
    """Send OTP to email for verification during signup"""
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get("email")

        if not email:
            return JsonResponse({"error": "Email is required"}, status=400)

        # Check if the email is already used
        if CustomUser.objects.filter(email=email).exists():
            return JsonResponse({"error": "Email already exists"}, status=400)

        otp = generate_otp()
        send_verification_email(email, otp)

        # Temporarily store OTP in the user model
        user, created = CustomUser.objects.get_or_create(email=email)
        user.otp = otp
        user.save()

        return JsonResponse({"message": "OTP sent successfully!"})

@csrf_exempt
def verify_email(request):
    """Verify the OTP sent to email"""
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get("email")
        otp = data.get("otp")

        user = CustomUser.objects.filter(email=email, otp=otp).first()

        if user:
            user.email_verified = True
            user.otp = None  # Clear OTP after verification
            user.save()
            return JsonResponse({"message": "Email verified successfully!"})
        else:
            return JsonResponse({"error": "Invalid OTP"}, status=400)

@csrf_exempt
def register_user(request):
    """Complete signup after email verification"""
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get("email")
        name = data.get("name")
        password = data.get("password")

        if not email or not password or not name:
            return JsonResponse({"error": "All fields are required"}, status=400)

        # Check if the user already exists
        user = CustomUser.objects.filter(email=email).first()
        if not user or not user.email_verified:
            return JsonResponse({"error": "Email not verified"}, status=400)
         
         # Validate Password
        try:
            validate_password(password)  # Django built-in password validation
        except ValidationError as e:
            return JsonResponse({"error": e.messages}, status=400)
 
        user.set_password(password)  # Set hashed password
        user.name = name
        user.save()
        login(request, user)

        return JsonResponse({"status": "success", "message": "Signup completed successfully!"})

@csrf_exempt
def login_user(request):
    """Login with email and password"""
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get("email")
        password = data.get("password")

        user = authenticate(email=email, password=password)

        if user:
            login(request, user)
            return JsonResponse({"message": "Login successful!"})
        else:
            return JsonResponse({"error": "Invalid credentials"}, status=400)


def home(request):
    return render(request, 'home.html')


def userlogin(request):
    return render(request, 'userlogin.html')

def userlogout(request):
    logout(request)
    return render(request, 'home.html')


def forgot_password(request):
    return render(request, 'forgot_password.html')

def reset_password_view(request, uidb64, token):
    return render(request, "reset_password.html", {"uidb64": uidb64, "token": token})


def update_password(request):
    if request.method == "POST":
        uidb64 = request.POST.get("uidb64")
        token = request.POST.get("token")
        new_password1 = request.POST.get("new_password1")
        new_password2 = request.POST.get("new_password2")

        # Validate password match
        if new_password1 != new_password2:
            return JsonResponse({"error": "Passwords do not match"}, status=400)

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)

            if not default_token_generator.check_token(user, token):
                return JsonResponse({"error": "Invalid or expired reset token"}, status=400)

            # Update password
            user.password = make_password(new_password1)  # Hash password
            user.save()
            messages.success(request, "Password updated successfully! You can now log in.")
            return redirect("/")  # ✅ Redirect to login page
        
        except (CustomUser.DoesNotExist, ValueError, TypeError):
            messages.error(request, "Invalid request")
            return redirect("reset_password", uidb64=uidb64, token=token)

    return JsonResponse({"error": "Invalid request"}, status=400)