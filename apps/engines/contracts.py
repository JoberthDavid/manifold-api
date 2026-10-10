from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EngineRequestContext:
    """
    Contexto de identidade utilizado em uma chamada de engine.

    O Manifold utiliza este contexto para representar o usuário
    autenticado que originou a operação.
    """

    user_id: str


class EngineClient(ABC):
    """
    Contrato base para clientes de engines integradas ao Manifold.

    Cada engine deve possuir um client próprio que implemente este
    contrato, mantendo isolados os detalhes de comunicação e
    autenticação da engine.
    """

    @property
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
        Executa uma operação disponibilizada pela engine.

        A implementação concreta é responsável por traduzir a
        operação para o protocolo específico da engine.
        """
        raise NotImplementedError
