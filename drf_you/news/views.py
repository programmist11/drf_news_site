import random

from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect
from rest_framework import generics, permissions, serializers, views, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import Account, Category, Ip, News
from .password_validation import validate_password
from .permissions import ReadOnlyOrIsReconfirmed
from .serializers import (EmailSerializer, NewsSerializer,
                          PasswordResetEnterCodeSerializer,
                          RegisterEnterCodeSerializer, UserLoginSerializer,
                          UserRegisterSerializer, UserSerializer)


class NewsViewSet(viewsets.ModelViewSet):
    queryset = News.objects.all()
    serializer_class = NewsSerializer
    permission_classes = [ReadOnlyOrIsReconfirmed]

    def perform_create(self, serializer):
        serializer.save(autor=self.request.user)


class RegisterAPIView(generics.CreateAPIView):
    serializer_class = UserRegisterSerializer
    queryset = User.objects.all()
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = UserRegisterSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            password2 = serializer.validated_data.get('password2')

            if User.objects.filter(email=email):
                raise serializers.ValidationError({email: "Пользователь с таким email уже существует"})
            if password != password2:
                raise serializers.ValidationError({password: "Пароль не совпадает"})

            validate_password(password)
            user = User(email=email, username=username)
            message_code = send_code(email)
            user.set_password(password)
            user.save()
            Account.objects.create(user=user, code=message_code)

            login(request, user)
            return redirect(f"/register/{user.id}/enter_code")
        return Response(serializer.errors)


class RegisterEnterCodeAPIView(generics.CreateAPIView):
    serializer_class = RegisterEnterCodeSerializer
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = RegisterEnterCodeSerializer(data=request.data)
        if serializer.is_valid():
            code_response = serializer.validated_data.get("code")
            user_id = kwargs.get('user_id')
            account = get_object_or_404(Account, user_id=user_id)
            if account.code == code_response:
                account.is_reconfirmed = True
                account.save()
                return redirect("/")
            else:
                raise serializers.ValidationError({code_response: "неверный код"})


class UserViewSet(viewsets.ModelViewSet):

    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]


class LogoutAPIView(views.APIView):

    def get(self, request):
        logout(request)
        return redirect("/")


class LoginAPIView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)

        if serializer.is_valid():
            username = serializer.validated_data.get("username")
            password = serializer.validated_data.get("password")

            user = User.objects.filter(Q(username=username) | Q(email=username)).first()
            if user:
                if not user.check_password(password):
                    raise serializers.ValidationError({password: "Неверный пароль"})
                else:
                    login(request, user)
                    return redirect("/")
            raise serializers.ValidationError({username: "Неверное имя пользователя или пароль"})


class PasswordResetAPIView(generics.GenericAPIView):
    serializer_class = EmailSerializer
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        serializer = EmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get("email")
            user = User.objects.filter(email=email).first()
            if user:
                message_code = send_code(email)
                try:
                    user.account.code = message_code
                    user.account.save()
                except ObjectDoesNotExist:
                    Account.objects.create(user=user, code=message_code)

                return redirect(f"/password_reset/{user.id}/enter_code")
            raise serializers.ValidationError({email: "неверная почта"})


class PasswordResetEnterCodeAPIView(generics.GenericAPIView):
    serializer_class = PasswordResetEnterCodeSerializer
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetEnterCodeSerializer(data=request.data)

        if serializer.is_valid():
            password = serializer.validated_data.get('password')
            password2 = serializer.validated_data.get('password2')
            code_request = serializer.validated_data.get("code")
            user_id = kwargs.get('user_id')
            if password == password2:
                user = User.objects.filter(pk=user_id).first()
                if user:
                    code_response = user.account.code
                    if code_response == code_request:
                        validate_password(password)
                        user.set_password(password)
                        user.save()
                        login(request, user)
                        return redirect("/")
                    raise serializers.ValidationError({"code": "Неверный код"})
                raise serializers.ValidationError({"username": "Пользователь не найден"})
            raise serializers.ValidationError({"password": "Пароли не совпадают"})
        return Response(serializer.errors)


def send_code(email, massage='Код подтверждения'):
    random.seed()
    message_code = str(random.randint(10000, 99999))
    send_mail(massage,
              message_code,
              settings.EMAIL_HOST_USER,
              [email],
              fail_silently=False
              )
    return message_code

