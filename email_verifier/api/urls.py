from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import RegisterView, EmailValidationView, LogoutView
from api.views import RegisterView, EmailValidationView, LogoutView, GetTokenView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("email_verify/", EmailValidationView.as_view(), name="validate_email"),
    path("email_verify/get-token/", GetTokenView.as_view(), name="get_token"),
]
