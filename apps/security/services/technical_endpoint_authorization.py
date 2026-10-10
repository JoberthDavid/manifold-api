from __future__ import annotations

from apps.security.models import (
    Service,
    ServiceTechnicalEndpoint,
    TechnicalEndpoint,
)


class TechnicalEndpointAuthorizationService:
    """
    Verifica se um serviço está autorizado a acessar um endpoint técnico.
    """

    @classmethod
    def is_authorized(
        cls,
        *,
        service: Service,
        endpoint: TechnicalEndpoint,
    ) -> bool:
        if not isinstance(service, Service):
            return False

        if not isinstance(endpoint, TechnicalEndpoint):
            return False

        if not service.enabled:
            return False

        if not endpoint.enabled:
            return False

        return ServiceTechnicalEndpoint.objects.filter(
            service=service,
            endpoint=endpoint,
            enabled=True,
        ).exists()