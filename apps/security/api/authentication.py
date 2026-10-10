from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from apps.security.services.service_credentials import (
    ServiceCredentialService,
)


class ServiceCredentialAuthentication(BaseAuthentication):
    """
    Autentica requisições internas entre serviços usando uma
    credencial técnica do Manifold.

    Header esperado:

        Authorization: Bearer <service-token>
    """

    keyword = "Bearer"

    def authenticate_header(self, request):
        return self.keyword

    def authenticate(self, request):
        authorization = request.headers.get("Authorization")

        if not authorization:
            return None

        parts = authorization.split()

        if len(parts) != 2 or parts[0].lower() != self.keyword.lower():
            raise AuthenticationFailed(
                "Credenciais de serviço inválidas."
            )

        token = parts[1].strip()

        if not token:
            raise AuthenticationFailed(
                "Credenciais de serviço inválidas."
            )

        credential = ServiceCredentialService.authenticate(
            token=token,
        )

        if credential is None:
            raise AuthenticationFailed(
                "Credenciais de serviço inválidas."
            )

        return credential, token