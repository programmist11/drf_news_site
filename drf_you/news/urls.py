from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views


router = DefaultRouter()
router.register(r'news', views.NewsViewSet, basename="news")
router.register(r'users', views.UserViewSet, basename="user")


urlpatterns = [
    path('', include(router.urls)),
    path('register/', views.RegisterAPIView.as_view(), name='register'),
    path('validate/<int:user_id>/', views.RegisterValidateAPIView.as_view(), name="register_validate"),

]
