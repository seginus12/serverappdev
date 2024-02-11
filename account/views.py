from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from .serializers import *
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from rest_framework import views
from .utils import send_otp_email, generate_otp
from .models import OneTimePassword, CustomUser
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework.authentication import TokenAuthentication


class RegisterUserView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data=request.data
        serializer=self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user=serializer.data
            otp_code = generate_otp()
            send_otp_email(user['email'], otp_code)
            return Response({
                'data': user,
                'message': 'Account has been succesfully created'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUserEmail(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request):
        otp_code = request.data.get('otp')
        try:
            otp_obj = OneTimePassword.objects.get(code=otp_code)
            user = otp_obj.user
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({
                    'message': "Account has been verified"
                }, status=status.HTTP_200_OK)
            return Response({
                'message': 'User already verified'
            }, status=status.HTTP_204_NO_CONTENT)
        except OneTimePassword.DoesNotExist:
            return Response({
                'message': 'Verification code is invaid or was not provided'
            }, status=status.HTTP_404_NOT_FOUND)
        

class LoginUserNo2FAView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserLoginNo2FASerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(
            serializer.validated_data,
            status=status.HTTP_202_ACCEPTED
        )


class LoginUser2FAView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserLogin2FASerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.create(serializer.validated_data)
        token = Token.objects.get(user=serializer.validated_data['user'])
        return Response(
            token.key,
            status=status.HTTP_201_CREATED
        )


class LoginUser2FaCheckOTPView(GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    serializer_class = UserLogin2FaCheckOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(
            serializer.validated_data,
            status=status.HTTP_202_ACCEPTED
        )


class SendNewOTPView(GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    serializer_class = SendNewOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        otp_obj = serializer.update(serializer.validated_data)
        return Response(
            otp_obj.code,
            status=status.HTTP_202_ACCEPTED
        )        
    

class GetUserView(GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = UserGetSerializer   
    def get(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = CustomUser.objects.get(email=serializer.validated_data['email'])
        return Response(
            {
                'id': user.id,
                'username': user.email,
                'is_verified': user.is_verified,
                'is_active': user.is_active,
                'is_admin': user.is_admin
            },
            status=status.HTTP_200_OK
        )


class ResetTokenView(APIView):
    def post(self, request):
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        for token in tokens:
            t, _ = BlacklistedToken.objects.get_or_create(token=token)
        return Response(status=status.HTTP_205_RESET_CONTENT)

    
# class GetOTPView(views.APIView):
#     # This view should be accessible also for unauthenticated users.
#     permission_classes = (permissions.AllowAny,)

#     def post(self, request, format=None):
#         serializer = GetOTPSerializer(data=self.request.data,
#             context={ 'request': self.request })
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data['user']
#         otp = serializer.create_otp(instance=user)
#         send_otp_email(user.email, otp.code)
#         return Response(f"Verification code has been sended to you email", status=status.HTTP_200_OK)
    