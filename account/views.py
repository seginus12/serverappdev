from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView, RetrieveUpdateDestroyAPIView
from .serializers import *
from rest_framework.response import Response
from rest_framework import generics, mixins, status
from rest_framework import permissions
from .utils import send_otp_email, generate_otp, check_user_permissions
from .models import OneTimePassword, CustomUser
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.apps import apps
from django.shortcuts import get_object_or_404
from rest_framework.request import Request
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.contrib.auth.decorators import permission_required
from django.core.exceptions import PermissionDenied


class RegisterUserView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data=request.data
        serializer=self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user=serializer.data
            otp_code = generate_otp()
            send_otp_email(user['email'], otp_code)
            return Response({
                'data': user,
                'message': 'Account has been succesfully created'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUserEmail(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request):
        otp_code = request.data.get('otp')
        try:
            otp_obj = OneTimePassword.objects.get(code=otp_code)
            user = otp_obj.user
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({
                    'message': "Account has been verified"
                }, status=status.HTTP_200_OK)
            return Response({
                'message': 'User already verified'
            }, status=status.HTTP_204_NO_CONTENT)
        except OneTimePassword.DoesNotExist:
            return Response({
                'message': 'Verification code is invaid or was not provided'
            }, status=status.HTTP_404_NOT_FOUND)
        

class LoginUserNo2FAView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserLoginNo2FASerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(
            serializer.validated_data,
            status=status.HTTP_202_ACCEPTED
        )


class LoginUser2FAView(GenericAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = UserLogin2FASerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.create(serializer.validated_data)
        token = Token.objects.get(user=serializer.validated_data['user'])
        message = serializer.validated_data['message']
        return Response(
            {token.key, message},
            status=status.HTTP_201_CREATED
        )


class LoginUser2FaCheckOTPView(GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    serializer_class = UserLogin2FaCheckOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(
            serializer.validated_data,
            status=status.HTTP_202_ACCEPTED
        )


class SendNewOTPView(GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)
    serializer_class = SendNewOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        otp_obj = serializer.update(serializer.validated_data)
        return Response(
            otp_obj.code,
            status=status.HTTP_202_ACCEPTED
        )        
    

class GetUserView(GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = UserGetSerializer   
    def get(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = CustomUser.objects.get(email=serializer.validated_data['email'])
        return Response(
            {
                'id': user.id,
                'username': user.email,
                'is_verified': user.is_verified,
                'is_active': user.is_active,
                'is_admin': user.is_admin
            },
            status=status.HTTP_200_OK
        )


class ResetJWTTokensView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)
    serializer_class = ResetJWTTokensSerializer

    def delete(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        current_token = serializer.data['refresh']
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        for token in tokens:
            if token.token != current_token:
                t, _ = BlacklistedToken.objects.get_or_create(token=token)
        return Response(
            data='All JWT tokens has been reseted',
            status=status.HTTP_205_RESET_CONTENT
            )
      

class BlacklistJWTTokensView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (JWTAuthentication,)

    def delete(self, request):
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        for token in tokens:
            t, _ = BlacklistedToken.objects.get_or_create(token=token)
        return Response(
            data='All JWT tokens has been blacklisted',
            status=status.HTTP_205_RESET_CONTENT
            )


class ResetTokensView(APIView, PermissionRequiredMixin):
    # permission_classes = (permissions.IsAdminUser,)
    permission_required = "delete_token"
    authentication_classes = (JWTAuthentication,)

    @check_user_permissions
    def delete(self, request, permission="delete_token"):
        # if check_user_permissions(request.user, "delete_token"):
        #     Token.objects.all().delete()
        #     return Response(
        #         data='All auth tokens has been reseted',
        #         status=status.HTTP_205_RESET_CONTENT
        #         )
        # else:
        #     raise PermissionDenied()
        return Response(status=status.HTTP_200_OK)


class GroupCRUDView(
    generics.GenericAPIView,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    mixins.CreateModelMixin
):
    authentication_classes = (JWTAuthentication,)
    serializer_class = GroupSerializer
    queryset = Group.objects.all()
    # permission_classes = [permissions.IsAdminUser,]

    def get(self, request: Request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request: Request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request: Request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)
    
    def post(self, request: Request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
    

class PermissionCRUDView(
    generics.GenericAPIView,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    mixins.CreateModelMixin
):
    authentication_classes = (JWTAuthentication,)
    serializer_class = PermissionSerializer
    queryset = Permission.objects.all()
    # permission_classes = [permissions.IsAdminUser,]

    def get(self, request: Request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request: Request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request: Request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)
    
    def post(self, request: Request, *args, **kwargs):
        return self.create(request, *args, **kwargs)
    

class UserGroupCRUDView(APIView,):
    authentication_classes = (JWTAuthentication,)
    serializer_class = UserGroupSerializer
    # permission_classes = [permissions.IsAdminUser,]

    def get(self, request: Request, *args, **kwargs):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_id = serializer.data['user_id']
        if user_id:
            user = CustomUser.objects.get(pk=user_id)
        else:
            user = request.user
        groups = user.groups.all()
        serializer = GroupSerializer(instance=groups, many=True)
        return Response(data=serializer.data, status=status.HTTP_200_OK)

    def post(self, request: Request, *args, **kwargs):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_id = serializer.data['user_id']
        if user_id:
            user = CustomUser.objects.get(pk=user_id)
        else:
            user = request.user
        groups = serializer.data['groups_id']
        user.groups.set(groups)
        return Response(status=status.HTTP_200_OK)

    def delete(self, request: Request, *args, **kwargs):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_id = serializer.data['user_id']
        if user_id:
            user = CustomUser.objects.get(pk=user_id)
        else:
            user = request.user
        groups = serializer.data['groups_id']
        for group in groups:
            user.groups.remove(group)
        return Response(status=status.HTTP_205_RESET_CONTENT)
    
    def put(self, request: Request, *args, **kwargs):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_id = serializer.data['user_id']
        if user_id:
            user = CustomUser.objects.get(pk=user_id)
        else:
            user = request.user
        groups = serializer.data['groups_id']
        for group in groups:
            user.groups.add(group)
        return Response(status=status.HTTP_200_OK)
    

class GroupPermissionCRUDView(APIView,):
    authentication_classes = (JWTAuthentication,)
    serializer_class = GroupPermissionSerializer
    # permission_classes = [permissions.IsAdminUser,]

    def get(self, request: Request, *args, **kwargs):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        group = get_object_or_404(Group, pk=serializer.data['group_id'])
        permissions = group.permissions.all()
        serializer = PermissionSerializer(instance=permissions, many=True)
        return Response(data=serializer.data, status=status.HTTP_200_OK)

    def post(self, request: Request, *args, **kwargs):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        permissions = serializer.data['permissions_id']
        group = get_object_or_404(Group, pk=serializer.data['group_id'])
        group.permissions.set(permissions)
        return Response(status=status.HTTP_200_OK)

    def delete(self, request: Request, *args, **kwargs):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        group = get_object_or_404(Group, pk=serializer.data['group_id'])
        permissions = serializer.data['permissions_id']
        for permission in permissions:
            group.permissions.remove(permission)
        return Response(status=status.HTTP_205_RESET_CONTENT)
    
    def put(self, request: Request, *args, **kwargs):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        group = get_object_or_404(Group, pk=serializer.data['group_id'])
        permissions = serializer.data['permissions_id']
        for permission in permissions:
            group.permissions.add(permission)
            print(permission)
        return Response(status=status.HTTP_200_OK)
    

# class GroupListCreateView(
#     generics.GenericAPIView, mixins.ListModelMixin, mixins.CreateModelMixin
# ):
#     serializer_class = PostSerializer
#     permission_classes = [permissions.IsAdminUser,]
#     queryset = Group.objects.all()

#     # def perform_create(self, serializer):
#     #     user = self.request.user
#     #     serializer.save(author=user)
#     #     return super().perform_create(serializer)

#     def get(self, request: Request, *args, **kwargs):
#         return self.list(request, *args, **kwargs)

#     def post(self, request: Request, *args, **kwargs):
#         return self.create(request, *args, **kwargs)