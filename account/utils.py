import random
import string
from django.core.mail import send_mail
from django.conf import settings
from .models import CustomUser, OneTimePassword


def generate_otp(length=settings.OTP_LENGTH):
    characters = string.digits
    otp = ''.join(random.choice(characters) for _ in range(length))
    return otp

def send_otp_email(email, otp):
    subject = 'Your OTP for Login'
    message = f'Your OTP is: {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    # user = CustomUser.objects.get(email=email)
    # OneTimePassword.objects.create(user=user, code=otp)
    send_mail(subject, message, from_email, recipient_list)