from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r'news', views.NewsViewSet, basename="news")
router.register(r'users', views.UserViewSet, basename="user")


urlpatterns = [
    path('', include(router.urls)),
    path('register/', views.RegisterAPIView.as_view(), name="register"),
    path('register/<int:user_id>/enter_code', views.RegisterEnterCodeAPIView.as_view(), name="register_id_enter_code"),
    path('login/', views.LoginAPIView.as_view(), name="login"),
    path('logout/', views.LogoutAPIView.as_view(), name="logout"),
    path('password_reset', views.PasswordResetAPIView.as_view(), name="password_reset")
]
