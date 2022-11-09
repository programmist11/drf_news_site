from rest_framework import permissions


class ReadOnlyOrIsReconfirmed(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):

        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.autor == request.user or request.user.is_superuser

    def has_permission(self, request, view):

        if request.method in permissions.SAFE_METHODS:
            return True

        if request.user.is_anonymous:
            return False

        if request.user.is_superuser:
            return True

        return request.user.account.is_reconfirmed
