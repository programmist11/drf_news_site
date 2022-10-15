from django.contrib.auth.password_validation import get_default_password_validators
from django.core.exceptions import ValidationError
from rest_framework import serializers


def validate_password(password, user=None, password_validators=None):

    errors = []
    if password_validators is None:
        password_validators = get_default_password_validators()
    for validator in password_validators:
        try:
            validator.validate(password, user)
        except ValidationError as error:
            errors.append(error)
    if errors:
        raise serializers.ValidationError({password: errors})



