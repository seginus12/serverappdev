from rest_framework import serializers
from .models import CustomUser, OTP
from django.contrib.auth import authenticate, get_user_model
from .utils import generate_otp
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()

class GetOTPSerializer(serializers.Serializer):
    """
    This serializer defines two fields for authentication:
      * username
      * password.
    It will try to authenticate the user with when validated.
    """
    email = serializers.CharField(
        label="Username",
        write_only=True
    )
    password = serializers.CharField(
        label="Password",
        # This will be used when the DRF browsable API is enabled
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )

    def validate(self, attrs):
        # Take username and password from request
        username = attrs.get('email')
        password = attrs.get('password')

        if username and password:
            # Try to authenticate the user using Django auth framework.
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)
            if not user:
                # If we don't have a regular user, raise a ValidationError
                msg = 'Access denied: wrong username or password.'
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = 'Both "username" and "password" are required.'
            raise serializers.ValidationError(msg, code='authorization')
        # We have a valid user, put it in the serializer's validated_data.
        # It will be used in the view.
        attrs['user'] = user
        return attrs
    
    def create_otp(self, instance):
        code = generate_otp()
        otp = OTP.objects.create(user=instance, code=code)
        return otp
    

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        # The default result (access/refresh tokens)
        data = super(CustomTokenObtainPairSerializer, self).validate(attrs)
        # Custom data you want to include
        data.update({'user': self.user.username})
        data.update({'id': self.user.id})
        # and everything else you want to send in the response
        return data
    

    # def update(self, instance):
    #     otp = generate_otp()
    #     instance.otp = otp
    #     instance.save()
    #     return instance
    

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
