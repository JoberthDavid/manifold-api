from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from apps.accounts.services import SessionService


class SessionAuthentication(BaseAuthentication):
    """
    Authenticates API requests using a Manifold session token.

    Expected header:

        Authorization: Bearer <session-token>
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
            raise AuthenticationFailed("Credenciais de autenticação inválidas.")

        token = parts[1].strip()

        if not token:
            raise AuthenticationFailed("Credenciais de autenticação inválidas.")

        user = SessionService.authenticate_session(token)

        if user is None:
            raise AuthenticationFailed("Credenciais de autenticação inválidas.")

        return user, token
