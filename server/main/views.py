from django.shortcuts import render, HttpResponse
from django.views.generic import View
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import generics
from .models import User
from .serializers import UserSerializer
from rest_framework import permissions
User = get_user_model()


class UserLoginView(View):
    def get(self, request):
        return render(request, 'main/login.html')

    def post(self, request, **kwargs):
        email = request.POST.get('email')
        password = request.POST.get('password')

        user = authenticate(request, username=email, password=password)
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


class UserDetail(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = (permissions.AllowAny,)
    queryset = User.objects.all()
    serializer_class = UserSerializer

