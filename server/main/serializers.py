from rest_framework import serializers
from .models import User


class UserSerializer(serializers.Serializer):
    def get_user(self, my_request):
        user = my_request.user
        
        return {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        }
