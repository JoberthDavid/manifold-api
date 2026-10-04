from django.core import mail
from django.test import TestCase, override_settings

from .email import (
    EmailDeliveryStatus,
    EmailMessage,
)
from .services import (
    DjangoEmailProvider,
    EmailService,
    EmailServiceFactory,
)


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="Manifold <noreply@manifold.local>",
)
class DjangoEmailProviderTests(TestCase):
    def setUp(self):
        self.message = EmailMessage(
            recipient="user@example.com",
            subject="Teste de e-mail",
            body="Esta é uma mensagem de teste.",
        )

    def test_send_email_successfully(self):
        provider = DjangoEmailProvider()

        result = provider.send(self.message)

        self.assertEqual(
            result.status,
            EmailDeliveryStatus.SENT,
        )
        self.assertTrue(result.is_sent)
        self.assertIsNone(result.error)

        self.assertEqual(len(mail.outbox), 1)

        sent_email = mail.outbox[0]

        self.assertEqual(
            sent_email.subject,
            "Teste de e-mail",
        )
        self.assertEqual(
            sent_email.body,
            "Esta é uma mensagem de teste.",
        )
        self.assertEqual(
            sent_email.to,
            ["user@example.com"],
        )
        self.assertEqual(
            sent_email.from_email,
            "Manifold <noreply@manifold.local>",
        )

    def test_send_email_with_custom_sender(self):
        message = EmailMessage(
            recipient="user@example.com",
            subject="Teste",
            body="Mensagem",
            sender="Sistema <system@example.com>",
        )

        provider = DjangoEmailProvider()

        result = provider.send(message)

        self.assertEqual(
            result.status,
            EmailDeliveryStatus.SENT,
        )

        self.assertEqual(len(mail.outbox), 1)

        sent_email = mail.outbox[0]

        self.assertEqual(
            sent_email.from_email,
            "Sistema <system@example.com>",
        )

    def test_send_email_with_reply_to(self):
        message = EmailMessage(
            recipient="user@example.com",
            subject="Teste",
            body="Mensagem",
            reply_to="support@example.com",
        )

        provider = DjangoEmailProvider()

        result = provider.send(message)

        self.assertEqual(
            result.status,
            EmailDeliveryStatus.SENT,
        )

        self.assertEqual(len(mail.outbox), 1)

        sent_email = mail.outbox[0]

        self.assertEqual(
            sent_email.reply_to,
            ["support@example.com"],
        )


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="Manifold <noreply@manifold.local>",
)
class EmailServiceTests(TestCase):
    def test_service_delegates_to_provider(self):
        provider = DjangoEmailProvider()
        service = EmailService(provider=provider)

        message = EmailMessage(
            recipient="user@example.com",
            subject="Teste do serviço",
            body="Mensagem enviada pelo EmailService.",
        )

        result = service.send(message)

        self.assertEqual(
            result.status,
            EmailDeliveryStatus.SENT,
        )
        self.assertEqual(len(mail.outbox), 1)

    def test_factory_creates_email_service(self):
        service = EmailServiceFactory.create()

        self.assertIsInstance(
            service,
            EmailService,
        )

        self.assertIsInstance(
            service.provider,
            DjangoEmailProvider,
        )