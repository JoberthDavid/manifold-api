from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from apps.engines.contracts import EngineClient, EngineRequestContext


class HttpEngineClient(EngineClient, ABC):
    """
    Implementação base para clients de engines acessadas via HTTP.

    Esta classe concentra a infraestrutura comum aos clients concretos,
    enquanto cada engine define suas próprias operações.
    """

    def __init__(
        self,
        *,
        base_url: str,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @abstractmethod
    def engine_name(self) -> str:
        """
        Retorna o nome lógico da engine.
        """
        raise NotImplementedError

    @abstractmethod
    def call(
        self,
        *,
        operation: str,
        context: EngineRequestContext,
        **kwargs: Any,
    ) -> Any:
        """
        Executa uma operação na engine.
        """
        raise NotImplementedError
