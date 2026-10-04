from dataclasses import dataclass

from apps.communications.email import EmailMessage
from apps.communications.services import EmailService


@dataclass(frozen=True)
class AuthenticationNotificationService:
    email_service: EmailService

    def send_authentication_code(
        self,
        *,
        recipient: str,
        verification_code: str,
    ):
        message = EmailMessage(
            recipient=recipient,
            subject="Código de autenticação — Manifold",
            body=(
                "Seu código de autenticação do Manifold é:\n\n"
                f"{verification_code}\n\n"
                "Este código é válido por 10 minutos.\n"
                "Se você não solicitou este código, ignore esta mensagem."
            ),
        )

        return self.email_service.send(message)