from django.shortcuts import render, HttpResponse
from django.views.generic import View
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import generics
from django.contrib.auth.models import User 
from .serializers import UserSerializer
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
User = get_user_model()
import logging


class UserLoginView(View):
    def get(self, request):
        return render(request, 'main/login.html')

    def post(self, request, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        logging.info(username)
        logging.info(password)
        if user is not None:
            login(request, user)
            return HttpResponseRedirect(request.GET.get('next'))
        else:
            raise AuthenticationFailed('Access denied: wrong username or password.')


class UserLogoutView(View):
    def get(self, request):
        logout(request)
        return HttpResponseRedirect("/")
    

class UserList(generics.ListCreateAPIView):
    permission_classes = (permissions.AllowAny,)
    queryset = User.objects.all()
    serializer_class = UserSerializer


class UserDetail(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserSerializer

    def get(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.get_user(request)

        return Response(
            user,
            status=status.HTTP_201_CREATED
        )
