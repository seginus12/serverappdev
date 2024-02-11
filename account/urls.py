from django.urls import path
from rest_framework_simplejwt import views as jwt_views
from .views import *
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenBlacklistView
)


urlpatterns = [
    path('register', RegisterUserView.as_view()),
    path('verify_email', VerifyUserEmail.as_view()),
    path('login', LoginUserNo2FAView.as_view()),
    path('login_2fa', LoginUser2FAView.as_view()),
    path('login_2fa_check_otp', LoginUser2FaCheckOTPView.as_view()),
    path('send_new_otp', SendNewOTPView.as_view()),
    path('get_user', GetUserView.as_view()),
    path('logout', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('refresh', TokenRefreshView.as_view(), name='token_refresh'),
    path('reset_jwt_tokens', ResetJWTTokensView.as_view(), name='reset_jwt_tokens'),
    path('reset_tokens', ResetTokensView.as_view(), name='reset-tokens'),
    # python manage.py flushexpiredtokens to delete expired blacklisted tokens    
]