from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView, RetrieveUpdateDestroyAPIView
from .serializers import *
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions
from .utils import send_otp_email, generate_otp
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


class ResetTokensView(APIView):
    permission_classes = (permissions.IsAdminUser,)
    authentication_classes = (JWTAuthentication,)

    def delete(self, request):
        Token.objects.all().delete()
        return Response(
            data='All auth tokens has been reseted',
            status=status.HTTP_205_RESET_CONTENT
            )


class CreateRoleView(APIView):
    permission_classes = (permissions.IsAdminUser,)
    authentication_classes = (JWTAuthentication,)
    serializer_class = CreateRoleSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.create(serializer.data)
        return Response(
            data=f"Group {serializer.data['name']} has been created.",
            status=status.HTTP_201_CREATED
        )


class GroupView(RetrieveUpdateDestroyAPIView):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer

    def get_object(self):
        obj = get_object_or_404(Group, name=self.request.data['name'])
        self.check_object_permissions(self.request, obj)
        return obj


# class RolesView(APIView):
#     permission_classes = (permissions.IsAdminUser,)
#     authentication_classes = (JWTAuthentication,)
#     serializer_class = RolesSerializer

#     def post(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         name = serializer.data['name']
#         group = Group.objects.create(name=name)
#         group.save()
#         return Response(
#             data=f"Group {name} has been created.",
#             status=status.HTTP_201_CREATED
#         )

#     def get(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         name = serializer.data['name']
#         try:
#             group = Group.objects.get(name=name)
#         except:
#             raise ObjectDoesNotExist("No such group.")
#         return Response(
#             data={
#                 'id': group.id,
#                 'name': group.name
#             },
#             status=status.HTTP_200_OK
#         )
    
#     def delete(self, request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         name = serializer.data['name']
#         try:
#             Group.objects.get(name=name).delete()
#         except:
#             raise ObjectDoesNotExist("No such group.")
#         return Response(
#             data=f"Group {name} has been deleted.",
#             status=status.HTTP_200_OK
#         )

#     def put(self, request):
#         pass


class PermissionsView(APIView):
    permission_classes = (permissions.IsAdminUser,)
    authentication_classes = (JWTAuthentication,)
    serializer_class = PermissionsSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = serializer.data['name']
        codename = serializer.data['codename']
        model = apps.get_model(app_label='account', model_name=serializer.data['content_type'])
        content_type = ContentType.objects.get_for_model(model)
        permission = Permission.objects.create(name=name, codename=codename, content_type=content_type)
        permission.save()
        return Response(
            data=f"Permission {codename} has been created.",
            status=status.HTTP_201_CREATED
        )

    def get(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = serializer.data['name']
        codename = serializer.data['codename']
        model = apps.get_model(app_label='account', model_name=serializer.data['content_type'])
        content_type = ContentType.objects.get_for_model(model)
        permission = Permission.objects.create(name=name, codename=codename, content_type=content_type)
        permission.save()
        return Response(
            data=f"Permission {codename} has been created.",
            status=status.HTTP_201_CREATED
        )
    
    def delete(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        name = serializer.data['name']
        try:
            Group.objects.get(name=name).delete()
        except:
            raise ObjectDoesNotExist("No such group.")
        return Response(
            data=f"Group {name} has been deleted.",
            status=status.HTTP_200_OK
        )

    def put(self, request):
        pass