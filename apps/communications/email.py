from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class EmailDeliveryStatus(str, Enum):
    SENT = "SENT"
    FAILED = "FAILED"


@dataclass(frozen=True)
class EmailMessage:
    recipient: str
    subject: str
    body: str
    sender: str | None = None
    reply_to: str | None = None


@dataclass(frozen=True)
class EmailDeliveryResult:
    status: EmailDeliveryStatus
    message: EmailMessage
    error: str | None = None

    @property
    def is_sent(self) -> bool:
        return self.status == EmailDeliveryStatus.SENT


class EmailProvider(Protocol):
    def send(self, message: EmailMessage) -> EmailDeliveryResult:
        ...