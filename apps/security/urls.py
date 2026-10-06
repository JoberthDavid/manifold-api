from django.urls import path

from apps.security.views import jwks_view


urlpatterns = [
    path(
        ".well-known/jwks.json",
        jwks_view,
        name="jwks",
    ),
]