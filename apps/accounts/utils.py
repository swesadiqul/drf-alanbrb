from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken
from django.template.loader import render_to_string
from django.conf import settings
import random


def generate_otp():
    return random.randint(100000, 999999)

def send_email(recipient_list, recipient_name):
    otp_code = generate_otp()
    subject = "Your OTP for Email Verification"
    
    html_message = render_to_string('accounts/send-otp.html', {
        'otp_code': otp_code,
        'name': recipient_name,
        'company_name': 'alanbrb',
        'support_email': 'support@example.com',
        'website_url': 'http://localhost:7000'
    })
    
    from_email = settings.EMAIL_HOST_USER

    send_mail(
        subject,
        "",
        from_email,
        recipient_list,
        html_message=html_message,
        fail_silently=False,
    )

    return otp_code


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    access_token = str(refresh.access_token)
    refresh_token = str(refresh)

    return {
        'access_token': access_token,
        'refresh_token': refresh_token
    }
