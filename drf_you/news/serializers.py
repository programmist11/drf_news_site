import random
from abc import ABC

from django.contrib.auth.models import User
from rest_framework import serializers

from .models import Account, News


def generate_code():
    random.seed()
    return str(random.randint(10000, 99999))


class NewsSerializer(serializers.HyperlinkedModelSerializer):
    autor = serializers.ReadOnlyField(source="autor.username")
    category = serializers.SlugRelatedField(slug_field="title", read_only=True)

    class Meta:
        exclude = ['views']
        model = News


class UserRegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        label="Пароль повторно",
        style={'input_type': 'password'}
    )
    password = serializers.CharField(
        label="Пароль",
        style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2']


class RegisterEnterCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=5)


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'groups', 'is_staff', 'is_active', 'is_superuser']


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(
        label="Имя пользователя",
        max_length=20,
    )
    password = serializers.CharField(
        label="Пароль",
        style={'input_type': 'password'}
    )


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetEnterCodeSerializer(serializers.Serializer):
    code = serializers.CharField(
        max_length=5,
        label="Код",
    )
    password = serializers.CharField(
        label="Пароль",
        style={'input_type': 'password'}
    )
    password2 = serializers.CharField(
        label="Пароль повторно",
        style={'input_type': 'password'}
    )





