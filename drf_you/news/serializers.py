import random
# from django.contrib.auth.password_validation import validate_password
from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
from rest_framework import serializers
from django.core.exceptions import ValidationError
from .models import Account, News
from rest_framework.response import Response
from .password_validation import validate_password


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

        validate_password(password)
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


class RegisterEnterCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=5)


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'groups', 'is_staff', 'is_active', 'is_superuser']


class UserLoginSerializer(serializers.Serializer):
    password = serializers.CharField(
        label="Пароль",
        style={'input_type': 'password'}
    )

    username = serializers.CharField(
        label="Имя пользователя",
        max_length=20,
    )


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()




