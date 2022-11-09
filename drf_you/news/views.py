import random

from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect
from rest_framework import generics, permissions, serializers, views, viewsets
from rest_framework.decorators import api_view
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.reverse import reverse

from .models import Account, Category, Ip, News
from .permissions import ReadOnlyOrIsReconfirmed
from .serializers import (EmailSerializer, NewsSerializer,
                          RegisterEnterCodeSerializer, UserLoginSerializer,
                          UserRegisterSerializer, UserSerializer)


@api_view(['GET'])
def api_root(request, format=None):
    return Response({
        'register': reverse('register', request=request, format=format),
    })


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
        data = {}
        if serializer.is_valid():
            user = serializer.save()

            login(request, user)
            return redirect(f"/register/{user.id}/enter_code")
        else:
            data = serializer.errors
            return Response(data)


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
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]


class LogoutAPIView(views.APIView):

    def get(self, request):
        logout(request)
        return redirect("/")




# class PasswordResetAPIView(views.APIView):
#
#     def post(self, request):
#         serializer = EmailSerializer(data=request.data)
#         if serializer.is_valid():
#             email = serializer.validated_data.get("email")
#             user = User.objects.filter(email=email).first()
#             if user:
#                 message_code = generate_code()
#                 send_mail('Код подтверждения',
#                           message_code,
#                           settings.EMAIL_HOST_USER,
#                           [email],
#                           fail_silently=False
#                           )
#                 Account.objects.update(user=user, code=message_code)
#                 return redirect(f"/password_reset/{user.id}/enter_code")
#             raise serializers.ValidationError({email: "неверная почта"})


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
    permission_classes = [permissions.IsAuthenticated]

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



def send_code(email, massage='Код подтверждения'):
    message_code = generate_code()
    send_mail(massage,
              message_code,
              settings.EMAIL_HOST_USER,
              [email],
              fail_silently=False
              )
    return message_code

def generate_code():
    random.seed()
    return str(random.randint(10000, 99999))
