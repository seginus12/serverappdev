from rest_framework import serializers
from .models import CustomUser, OneTimePassword
from django.contrib.auth import authenticate, get_user_model
from .utils import generate_otp, send_otp_email, get_valid_refresh_count
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authtoken.models import Token
from django.conf import settings
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
import datetime
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
import requests
import logging 
import string
import random


User = get_user_model()
    

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=64, min_length=8, write_only=True)
    password2 = serializers.CharField(max_length=64, min_length=8, write_only=True)

    class Meta:
        model=CustomUser
        fields=['email', 'password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password')
        if password != password2:
            raise serializers.ValidationError("Passwords do not match")
        return attrs
        

    def create(self, validated_data):
        user = CustomUser(
            email=validated_data["email"],
        )
        user.set_password(validated_data["password"])
        user.save()
        user_group = Group.objects.get(name="User").pk
        user.groups.add(user_group)
        return user
    

class UserLoginNo2FASerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=64, label="Username", write_only=True)
    password = serializers.CharField(label="Password", style={'input_type': 'password'}, trim_whitespace=False, write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ['email', 'password',]

    def validate(self, attrs):
        username = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')
        if username and password:
            user = authenticate(request=request, username=username, password=password)
            if not user:
                raise AuthenticationFailed('Access denied: wrong username or password.')
        else:
            raise AuthenticationFailed('Both "username" and "password" are required.')
        if get_valid_refresh_count(user=user) > settings.MAX_JWT_TOKENS:
            message = 'You have to many open sessions. Logout from other devices.'
        else:
            message = ''       
        tokens = user.tokens()
        return {
            'username': user.email,
            'access_token': tokens['access'],
            'refresh_token': tokens['refresh'],
            'message': message 
        }


class UserLogin2FASerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=64, label="Username", write_only=True)
    password = serializers.CharField(label="Password", style={'input_type': 'password'}, trim_whitespace=False, write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ['email', 'password',]

    def validate(self, attrs):
        username = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')
        if username and password:
            user = authenticate(request=request, username=username, password=password)
            if not user:
                raise AuthenticationFailed('Access denied: wrong username or password.')
        else:
            raise AuthenticationFailed('Both "username" and "password" are required.')
        # Trying to delete user's token if exists
        if get_valid_refresh_count(user=user) > settings.MAX_JWT_TOKENS:
            attrs['message'] = 'You have to many open sessions. Logout from other devices.'
        else:
            attrs['message'] = ''
        try:
            user.auth_token.delete()
        except:
            pass
        finally:
            Token.objects.create(user=user)
        attrs['user'] = user
        return attrs
        
    def create(self, validated_data):
        user = validated_data['user']
        otp_code = generate_otp()
        try:
            OneTimePassword.objects.filter(user=user).delete()
        except:
            pass
        finally:
            otp_odject = OneTimePassword(
                user=user,
                code=otp_code,
            )
            otp_odject.save()
        # send_otp_email(user.email, otp_code)
        print(otp_code)
        return otp_odject
    

class UserLogin2FaCheckOTPSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=64, label="Username", write_only=True)
    otp_code = serializers.CharField(max_length=6, label="otp_code", write_only=True)

    def validate(self, attrs):
        user = CustomUser.objects.get(email=attrs.get('email'))
        otp_obj = OneTimePassword.objects.get(user=user)
        if otp_obj.attemts >= settings.MAX_OTP_ATTEMPTS:
            raise serializers.ValidationError("You have reached your attempt limit. Request new verification code.", code='authorization')
        if ((datetime.datetime.now() - otp_obj.created_at.replace(tzinfo=None)).total_seconds() / 60 ) > settings.OTP_TIME_LIVE:
            raise serializers.ValidationError("Verification code has expired. Request new one.", code='authorization')
        user_otp_code = otp_obj.code
        if str(user_otp_code) != attrs['otp_code']:
            otp_obj.attemts += 1
            otp_obj.save()
            raise serializers.ValidationError("Wrong verification code.", code='authorization')
        tokens = user.tokens()
        return {
            'username': user.email,
            'access': tokens['access'],
            'refresh': tokens['refresh']
        }


class SendNewOTPSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=64, label="Username", write_only=True)

    def validate(self, attrs):
        user = CustomUser.objects.get(email=attrs.get('email'))
        if not user:
            raise AuthenticationFailed('User does not exists.')
        attrs['user'] = user
        return attrs
    
    def update(self, attrs):
        user = attrs['user']
        try:
            OneTimePassword.objects.filter(user=user).delete()
        except:
            pass
        finally:
            otp_obj = OneTimePassword(
            user=user,
            code=generate_otp(),
            )
            otp_obj.save()
        # Send to email
        return otp_obj


class UserGetSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=64, label="Username", write_only=True)

    class Meta:
        model = CustomUser
        fields = ["email"]
        

class ResetJWTTokensSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=255)


class GroupSerializer(serializers.ModelSerializer):
    name = serializers.CharField(max_length=50)

    class Meta:
        model = Group
        fields = ["id", "name"]


class PermissionSerializer(serializers.ModelSerializer):
    # name = serializers.CharField(max_length=50)

    class Meta:
        model = Permission
        fields = "__all__"


class UserGroupSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(required=False, default=None)
    groups_id = serializers.ListField(required=False, default=None)


class GroupPermissionSerializer(serializers.Serializer):
    group_id = serializers.IntegerField()
    permissions_id = serializers.ListField(required=False, default=[])


class UserLoginOAuthSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=64, label="code")

    def validate(self, attrs):
        return attrs
    
    def login(self, attrs, my_request):
        # code = my_request.GET.get('code')
        code = attrs['code']
        headers={
            "Cache-Control": "no-cache",
            "Content-Type": "application/x-www-form-urlencoded"
            }
        query_params = {
            "client_id": settings.CLIENT_ID,
            "client_secret": settings.CLIENT_SECRET,
            "code": code,
            "code_verifier": settings.CODE_VERIFIER,
            "grant_type": "authorization_code",
            "redirect_uri": settings.REDIRECT_URL
        }
        # logging.info(query_params)
        response = requests.post(f"{settings.OAUTH_SERVER_URL}oauth/token/", headers=headers, data=query_params)
        token = response.json()['access_token']
        if not token:
            # logging.info(response.text)
            raise AuthenticationFailed(f'Authentication failed.\n {response.text}')
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(f"{settings.OAUTH_SERVER_URL}account/user", headers=headers)
        username = response.json()['username']
        try:
            temp_email = username + '@oauth.ru'
            password = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(8, 12)))
            user = CustomUser(email=temp_email, password=password)
            user.save()
        except:
            AuthenticationFailed(f'Error during user creation.')
        tokens = user.tokens()
        return {
            'username': user.email,
            'access_token': tokens['access'],
            'refresh_token': tokens['refresh'], 
        }

        # if username and password:
        #     user = authenticate(request=request, username=username, password=password)
        #     if not user:
        #         raise AuthenticationFailed('Access denied: wrong username or password.')
        # else:
        #     raise AuthenticationFailed('Both "username" and "password" are required.')
        # if get_valid_refresh_count(user=user) > settings.MAX_JWT_TOKENS:
        #     message = 'You have to many open sessions. Logout from other devices.'
        # else:
        #     message = ''       
        # tokens = user.tokens()
        # return {
        #     'username': user.email,
        #     'access_token': tokens['access'],
        #     'refresh_token': tokens['refresh'],
        #     'message': message 
        # }