from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import GetOTPSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from rest_framework import views
from .utils import send_otp_email
from .models import OTP


class GetOTPView(views.APIView):
    # This view should be accessible also for unauthenticated users.
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = GetOTPSerializer(data=self.request.data,
            context={ 'request': self.request })
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        otp = serializer.create_otp(instance=user)
        send_otp_email(user.email, otp.code)
        return Response(f"Verification code has been sended to you email", status=status.HTTP_200_OK)