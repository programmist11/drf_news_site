from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r'news', views.NewsViewSet, basename="news")
router.register(r'users', views.UserViewSet, basename="user")


urlpatterns = [
    path('', include(router.urls)),
    path('register/', views.RegisterAPIView.as_view(), name="register"),
    path('validate/<int:user_id>/', views.RegisterValidateAPIView.as_view(), name="register_validate"),
    path('login/', views.LoginAPIView.as_view(), name="login"),
    path('logout/', views.LogoutAPIView.as_view(), name="logout"),
    path('forgot_password', views.ForgotPasswordAPIView.as_view(), name="forgot_password")
]
