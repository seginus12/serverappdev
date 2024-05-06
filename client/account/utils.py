import random
import string
import base64
import hashlib
from django.core.mail import send_mail
from django.conf import settings
from .models import CustomUser, OneTimePassword
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
import datetime
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied


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

def get_valid_refresh_count(user):
    user_tokens = OutstandingToken.objects.filter(user=user)
    user_blacklisted_tokens = BlacklistedToken.objects.all()
    vaild_tokens_count = 0
    flag = False
    for token in user_tokens:
        for blacklisted_token in user_blacklisted_tokens:
            if token.token == blacklisted_token.token.token:
                flag = True
                break
        if flag:
            flag = False
            continue
        if (token.expires_at.replace(tzinfo=None) - datetime.datetime.now()).total_seconds() > 0:
            vaild_tokens_count += 1
    # print(vaild_tokens_count)
    return vaild_tokens_count

def check_perm(user: CustomUser, permission: string):
    groups = Group.objects.filter(user=user)
    for group in groups:
        permissions = group.permissions.all()
        for perm in permissions:
            if perm.codename == permission:
                return True
    return False

def check_group(user: CustomUser, group: string):
    groups = Group.objects.filter(user=user)
    for _group in groups:
        if _group.name == group:
            return True
    return False

def check_user_permissions(permission):
    def decorator(function):
        def wrapper(viewClass, request, pk=None):
            if check_perm(request.user, permission):
                result = function(viewClass, request)
            else:
                raise PermissionDenied()
            return result
        return wrapper
    return decorator

def check_user_group(group):
    def decorator(function):
        def wrapper(viewClass, request):
            if check_group(request.user, group):
                result = function(viewClass, request)
            else:
                raise PermissionDenied()
            return result
        return wrapper
    return decorator

def generate_code_verifier():
    code_verifier = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(43, 128)))
    return code_verifier

def generate_code_challenge(code_verifier):
    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8').replace('=', '')
    return code_challenge
