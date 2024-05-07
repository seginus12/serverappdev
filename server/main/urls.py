from django.urls import path
from .views import *


urlpatterns = [
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('logout/', UserLogoutView.as_view(), name='user-logout'),
    path('users/', UserList.as_view(), name='user-list'),
    path('user/', UserDetail.as_view(), name='user-detail'),
]