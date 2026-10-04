from django.urls import path

from .views import (
    LoginView,
    LogoutView,
    MeView,
    TwoFactorVerifyView,
)


app_name = "accounts-api"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("2fa/verify/", TwoFactorVerifyView.as_view(), name="two-factor-verify"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("me/", MeView.as_view(), name="me"),
]
