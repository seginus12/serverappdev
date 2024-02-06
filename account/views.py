from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import LoginSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from rest_framework import views
from .utils import send_otp_email


class LoginView(views.APIView):
    # This view should be accessible also for unauthenticated users.
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = LoginSerializer(data=self.request.data,
            context={ 'request': self.request })
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        serializer.update(instance=user)
        send_otp_email(user.email, user.otp)
        return Response(user.otp, status=status.HTTP_202_ACCEPTED)
