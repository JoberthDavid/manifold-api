from django.conf import settings
from django.core.mail import EmailMessage as DjangoEmailMessage

from .email import (
    EmailDeliveryResult,
    EmailDeliveryStatus,
    EmailMessage,
    EmailProvider,
)


class DjangoEmailProvider:
    """
    Implementação de EmailProvider utilizando o backend
    de e-mail configurado pelo Django.
    """

    name = "django"

    def send(self, message: EmailMessage) -> EmailDeliveryResult:
        sender = message.sender or settings.DEFAULT_FROM_EMAIL

        email = DjangoEmailMessage(
            subject=message.subject,
            body=message.body,
            from_email=sender,
            to=[message.recipient],
            reply_to=[message.reply_to] if message.reply_to else None,
        )

        try:
            email.send(fail_silently=False)
        except Exception as exc:
            return EmailDeliveryResult(
                status=EmailDeliveryStatus.FAILED,
                message=message,
                error=str(exc),
            )

        return EmailDeliveryResult(
            status=EmailDeliveryStatus.SENT,
            message=message,
        )


class EmailService:
    """
    Serviço de aplicação responsável pelo envio de mensagens
    de e-mail através de um provider configurado.
    """

    def __init__(self, provider: EmailProvider):
        self.provider = provider

    def send(self, message: EmailMessage) -> EmailDeliveryResult:
        return self.provider.send(message)


class EmailServiceFactory:
    """
    Factory responsável por construir a implementação padrão
    do serviço de e-mail da aplicação.
    """

    @classmethod
    def create(cls) -> EmailService:
        provider = DjangoEmailProvider()
        return EmailService(provider=provider)