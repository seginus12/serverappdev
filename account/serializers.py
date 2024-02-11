from rest_framework import serializers
from .models import CustomUser, OneTimePassword
from django.contrib.auth import authenticate, get_user_model
from .utils import generate_otp, send_otp_email
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authtoken.models import Token
from django.conf import settings
import datetime

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
        user.auth_token.delete()
        Token.objects.create(user=user)
        attrs['user'] = user
        return attrs
        
    def create(self, validated_data):
        user = validated_data['user']
        otp_code = generate_otp()
 #       otp_expiry = datetime.now() + timedelta(minutes = 10)
        otp_odject = OneTimePassword.objects.get(user=user)
        if not otp_odject:
            otp_odject = OneTimePassword(
                user=user,
                code=otp_code,
    #           otp_expiry=otp_expiry,
    #           max_otp_try=settings.MAX_OTP_TRY
            )
        send_otp_email(user.email, otp_code)
        return otp_odject
    

class UserLogin2FaCheckOTPSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=64, label="Username", write_only=True)
    otp_code = serializers.CharField(max_length=6, label="otp_code", write_only=True)

    def validate(self, attrs):
        user = CustomUser.objects.get(email=attrs.get('email'))
        otp_obj = OneTimePassword.objects.get(user=user)
        if otp_obj.attemts >= settings.MAX_OTP_ATTEMPTS:
            raise serializers.ValidationError("You have reached your attempt limit. Request new verification code.")
        if ((datetime.datetime.now() - otp_obj.updated_at.replace(tzinfo=None)).total_seconds() / 60 ) > settings.OTP_TIME_LIVE:
            raise serializers.ValidationError("Verification code has expired. Request new one.")
        user_otp_code = otp_obj.code
        if str(user_otp_code) != attrs['otp_code']:
            otp_obj.attemts += 1
            otp_obj.save()
            raise AuthenticationFailed("Wrong verification code.")
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
        email = attrs['user']
        otp_obj = OneTimePassword.objects.get(user=email)
        otp_obj.code = generate_otp()
        otp_obj.attemts = 0
        send_otp_email(email=email, otp=otp_obj.code)
        otp_obj.save()
        return otp_obj


class UserGetSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=64, label="Username", write_only=True)

    class Meta:
        model = CustomUser
        fields = ["email"]


# class LoginSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = CustomUser
#         fields = (
#         #    "id",
#             "email",
#             "password",
#         #   "password2"
#         )
#  #       read_only_fields = ("id",)

#     def validate(self, data):
#         username = data.get('email')
#         password = data.get('password')

#         if username and password:
#             user = authenticate(request=self.context.get('request'),
#                                 username=username, password=password)
#             if not user:
#                 msg = _('Unable to log in with provided credentials.')
#                 raise serializers.ValidationError(msg, code='authorization')
#         else:
#             msg = _('Must include "username" and "password".')
#             raise serializers.ValidationError(msg, code='authorization')
#         return data
    

#     def update(self, validated_data):
#         otp = generate_otp()
#  #       otp_expiry = datetime.now() + timedelta(minutes = 10)

#         user = CustomUser(
#             email=validated_data["email"],
#             otp=otp,
#  #           otp_expiry=otp_expiry,
#  #           max_otp_try=settings.MAX_OTP_TRY
#         )
#         user.set_password(validated_data["password"])
#         user.save()
#  #       send_otp(validated_data["phone_number"], otp)
#         return user


# class GetOTPSerializer(serializers.Serializer):
#     """
#     This serializer defines two fields for authentication:
#       * username
#       * password.
#     It will try to authenticate the user with when validated.
#     """
#     email = serializers.CharField(
#         label="Username",
#         write_only=True
#     )
#     password = serializers.CharField(
#         label="Password",
#         # This will be used when the DRF browsable API is enabled
#         style={'input_type': 'password'},
#         trim_whitespace=False,
#         write_only=True
#     )

#     def validate(self, attrs):
#         # Take username and password from request
#         username = attrs.get('email')
#         password = attrs.get('password')

#         if username and password:
#             # Try to authenticate the user using Django auth framework.
#             user = authenticate(request=self.context.get('request'),
#                                 username=username, password=password)
#             if not user:
#                 # If we don't have a regular user, raise a ValidationError
#                 msg = 'Access denied: wrong username or password.'
#                 raise serializers.ValidationError(msg, code='authorization')
#         else:
#             msg = 'Both "username" and "password" are required.'
#             raise serializers.ValidationError(msg, code='authorization')
#         # We have a valid user, put it in the serializer's validated_data.
#         # It will be used in the view.
#         attrs['user'] = user
#         return attrs
    
#     def create_otp(self, instance):
#         code = generate_otp()
#         otp = OneTimePassword.objects.create(user=instance, code=code)
#         return otp
    

# class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
#     def validate(self, attrs):
#         # The default result (access/refresh tokens)
#         data = super(CustomTokenObtainPairSerializer, self).validate(attrs)
#         # Custom data you want to include
#         data.update({'user': self.user.username})
#         data.update({'id': self.user.id})
#         # and everything else you want to send in the response
#         return data