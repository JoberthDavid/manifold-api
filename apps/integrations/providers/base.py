from __future__ import annotations

from abc import ABC, abstractmethod


class SecretProvider(ABC):
    """Contrato para provedores externos de secrets."""

    @abstractmethod
    def set_secret(
        self,
        *,
        name: str,
        value: str,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def redeploy(self) -> None:
        raise NotImplementedError
    