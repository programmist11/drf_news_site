from django.shortcuts import redirect
from rest_framework.response import Response
from .models import News, Category, Ip, Account
from .permissions import IsOwnerOrReadOnly
from .serializers import NewsSerializer, UserRegisterSerializer, UserSerializer, RegisterValidSerializer
from django.shortcuts import get_object_or_404
from rest_framework import viewsets, permissions, generics, status
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny
from django.contrib.auth import login, logout
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.reverse import reverse


@api_view(['GET'])
def api_root(request, format=None):
    return Response({
        'register': reverse('register', request=request, format=format),
    })


class NewsViewSet(viewsets.ModelViewSet):
    queryset = News.objects.all()
    serializer_class = NewsSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly,
                          IsOwnerOrReadOnly]

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
            return redirect(f'/validate/{user.id}')
        else:
            data = serializer.errors
            return Response(data)


class RegisterValidateAPIView(generics.CreateAPIView):
    serializer_class = RegisterValidSerializer
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        data = {}
        serializer = RegisterValidSerializer(data=request.data)
        if serializer.is_valid():
            code_response = serializer.validated_data.get("code")
            user_id = kwargs.get('user_id')
            code_base = get_object_or_404(Account, user_id=user_id).code
            if code_base == code_response:
                user = User.objects.get(pk=user_id)
                user.is_staff = True
                user.save()
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









