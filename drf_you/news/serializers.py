import random

from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
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
        fields = ['username', 'email', "password", "password2"]

    def save(self, *args, **kwargs):
        email = self.validated_data['email']
        username = self.validated_data['username']
        password = self.validated_data['password']
        password2 = self.validated_data['password2']
        if User.objects.filter(email=email):
            raise serializers.ValidationError({email: "Пользователь с таким email уже существует"})
        if password != password2:
            raise serializers.ValidationError({password: "Пароль не совпадает"})
        if len(password) < 8:
            raise serializers.ValidationError({password: "Пароль должен быть больше 7 символов"})
        user = User(email=email, username=username)
        message = generate_code()
        send_mail('Код подтверждения',
                  message,
                  settings.EMAIL_HOST_USER,
                  [email],
                  fail_silently=False
                  )
        user.set_password(password)
        user.save()
        Account.objects.create(user=User.objects.last(), code=message)
        return user


class RegisterValidSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=5)

    def save(self, **kwargs):
        pass


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'groups']