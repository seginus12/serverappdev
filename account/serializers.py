from rest_framework import serializers
from .models import CustomUser, OneTimePassword
from django.contrib.auth import authenticate, get_user_model
from .utils import generate_otp, send_otp_email, get_valid_refresh_count
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authtoken.models import Token
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
import datetime
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken

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
        if get_valid_refresh_count(user=user) >= settings.MAX_JWT_TOKENS:
            raise AuthenticationFailed('You have too many open sessions. Logout from other devices and try again.')
        tokens = user.tokens()
        return {
            'username': user.email,
            'access_token': tokens['access'],
            'refresh_token': tokens['refresh'],
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
            raise AuthenticationFailed('You have to many opened sessions. Logout from other devices and try again.')
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


class UserGetSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=64, label="Username", write_only=True)

    class Meta:
        model = CustomUser
        fields = ["email"]
        

class ResetJWTTokensSerializer(serializers.Serializer):
    refresh = serializers.CharField(max_length=255)

