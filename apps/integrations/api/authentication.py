from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from apps.accounts.models import User
from apps.accounts.services import SessionService
from apps.security.models import ServiceCredential
from apps.security.services.service_credentials import (
    ServiceCredentialService,
)


class IntegrationRequestAuthentication(BaseAuthentication):
    """
    Authenticates user sessions and service credentials for integrations.
    """

    keyword = "Bearer"

    def authenticate_header(self, request):
        return self.keyword

    def authenticate(self, request):
        authorization = request.headers.get("Authorization")

        if not authorization:
            return None

        parts = authorization.split()

        if (
            len(parts) != 2
            or parts[0].lower() != self.keyword.lower()
        ):
            raise AuthenticationFailed(
                "Credenciais de autenticação inválidas."
            )

        token = parts[1].strip()

        if not token:
            raise AuthenticationFailed(
                "Credenciais de autenticação inválidas."
            )

        user = SessionService.authenticate_session(token)

        if user is not None:
            return user, token

        credential = ServiceCredentialService.authenticate(
            token=token,
        )

        if credential is not None:
            return credential, token

        raise AuthenticationFailed(
            "Credenciais de autenticação inválidas."
        )
