from django.urls import path, re_path
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
    path('blacklist_jwt_tokens', BlacklistJWTTokensView.as_view(), name='blacklist_jwt_tokens'),
    path('reset_tokens', ResetTokensView.as_view(), name='reset-tokens'),

    re_path('group/(?P<pk>\w+|)', GroupCRUDView.as_view(), name='group_crud'),
    re_path('permission/(?P<pk>\w+|)', PermissionCRUDView.as_view(), name='permission_crud'),
    path('user_group', UserGroupCRUDView.as_view(), name='user_group_crud'),
    path('group_permission', GroupPermissionCRUDView.as_view(), name='group_permission_crud')
    # python manage.py flushexpiredtokens to delete expired blacklisted tokens    
]