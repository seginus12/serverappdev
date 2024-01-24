from django.urls import path, include, re_path
from rest_framework_simplejwt import views as jwt_views
from rest_framework_swagger.views import get_swagger_view


urlpatterns = [
    re_path(r'^auth/', include('djoser.urls')),
    # re_path(r'^auth/', include('djoser.urls.authtoken')),
]