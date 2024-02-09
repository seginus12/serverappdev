from django.urls import path, include, re_path
from rest_framework_simplejwt import views as jwt_views
from rest_framework_swagger.views import get_swagger_view
from .views import RegisterUserView, VerifyUserEmail, LoginUserView, GetUserView
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenBlacklistView
)


urlpatterns = [
    path('register', RegisterUserView.as_view()),
    path('verify_email', VerifyUserEmail.as_view()),
    path('login', LoginUserView.as_view()),
    path('get_user', GetUserView.as_view()),
    path('logout', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('refresh', TokenRefreshView.as_view(), name='token_refresh'),
    # python manage.py flushexpiredtokens to delete expired blacklisted tokens    
]