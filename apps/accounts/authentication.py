from dataclasses import dataclass
from enum import Enum

from .models import Session, User
from .services import SessionService


class CredentialAuthenticationStatus(str, Enum):
    """Resultado da validação de e-mail e senha."""

    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    INACTIVE_USER = "INACTIVE_USER"
    VALID = "VALID"


@dataclass(frozen=True)
class CredentialAuthenticationResult:
    """Resultado da primeira etapa da autenticação."""

    status: CredentialAuthenticationStatus
    user: User | None = None

    @property
    def is_valid(self) -> bool:
        return self.status == CredentialAuthenticationStatus.VALID


class AuthenticationStatus(str, Enum):
    """Estado final da tentativa de autenticação."""

    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    INACTIVE_USER = "INACTIVE_USER"
    TWO_FACTOR_REQUIRED = "TWO_FACTOR_REQUIRED"
    AUTHENTICATED = "AUTHENTICATED"


@dataclass(frozen=True)
class AuthenticationResult:
    """Resultado do processo de autenticação."""

    status: AuthenticationStatus
    user: User | None = None
    session: Session | None = None
    token: str | None = None
    challenge_id: str | None = None

    @property
    def is_authenticated(self) -> bool:
        return self.status == AuthenticationStatus.AUTHENTICATED

    @property
    def requires_two_factor(self) -> bool:
        return self.status == AuthenticationStatus.TWO_FACTOR_REQUIRED


class AuthenticationService:
    """Autenticação de usuários e criação das respectivas sessões."""

    @classmethod
    def authenticate_credentials(
        cls,
        email: str,
        password: str,
    ) -> CredentialAuthenticationResult:
        """
        Valida as credenciais do usuário.

        Esta operação não cria sessão e não produz token.
        """

        if not email or not password:
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INVALID_CREDENTIALS
            )

        normalized_email = email.strip()

        try:
            user = User.objects.get(email__iexact=normalized_email)
        except User.DoesNotExist:
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INVALID_CREDENTIALS
            )

        if not user.is_active:
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INACTIVE_USER,
                user=user,
            )

        if not user.check_password(password):
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INVALID_CREDENTIALS
            )

        return CredentialAuthenticationResult(
            status=CredentialAuthenticationStatus.VALID,
            user=user,
        )

    @classmethod
    def requires_two_factor(cls, user: User) -> bool:
        """
        Determina se a autenticação deve prosseguir para o segundo fator.

        A implementação de 2FA ainda não existe.
        Portanto, neste estágio, nenhum usuário exige segundo fator.

        Este método existe como ponto explícito de extensão para a futura
        política de autenticação multifator.
        """

        return False

    @classmethod
    def login(
        cls,
        email: str,
        password: str,
        *,
        ip_address=None,
        user_agent="",
        duration=None,
    ) -> AuthenticationResult:
        """
        Executa o fluxo completo de autenticação.

        A sessão somente é criada quando a autenticação estiver concluída.
        """

        credentials = cls.authenticate_credentials(
            email=email,
            password=password,
        )

        if credentials.status == CredentialAuthenticationStatus.INVALID_CREDENTIALS:
            return AuthenticationResult(
                status=AuthenticationStatus.INVALID_CREDENTIALS
            )

        if credentials.status == CredentialAuthenticationStatus.INACTIVE_USER:
            return AuthenticationResult(
                status=AuthenticationStatus.INACTIVE_USER,
                user=credentials.user,
            )

        user = credentials.user

        if user is None:
            return AuthenticationResult(
                status=AuthenticationStatus.INVALID_CREDENTIALS
            )

        if cls.requires_two_factor(user):
            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_REQUIRED,
                user=user,
            )

        session, token = SessionService.create_session(
            user,
            ip_address=ip_address,
            user_agent=user_agent,
            duration=duration,
        )

        return AuthenticationResult(
            status=AuthenticationStatus.AUTHENTICATED,
            user=user,
            session=session,
            token=token,
        )

    @classmethod
    def logout(cls, token: str) -> bool:
        """Revoga a sessão associada ao token."""

        return SessionService.revoke_session(token)