from django.urls import path, include, re_path
from rest_framework_simplejwt import views as jwt_views
from rest_framework_swagger.views import get_swagger_view
from .views import GetOTPView


urlpatterns = [
    re_path(r'^auth/', include('djoser.urls')),
    path('login/', GetOTPView.as_view())    
    # re_path(r'^auth/', include('djoser.urls.authtoken')),
]