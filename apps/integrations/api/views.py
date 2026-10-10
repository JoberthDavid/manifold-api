from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.integrations.gateway import IntegrationGateway
from apps.integrations.models import Integration, IntegrationOperation
from apps.security.api.authentication import ServiceCredentialAuthentication
from apps.security.api.permissions import IsServiceAuthenticated
from apps.security.models import TechnicalEndpoint
from apps.security.services.technical_endpoint_authorization import (
    TechnicalEndpointAuthorizationService,
)


class IntegrationExecuteView(APIView):
    authentication_classes = (ServiceCredentialAuthentication,)
    permission_classes = (IsServiceAuthenticated,)

    def get(self, request, integration_slug, operation_slug):
        return self._execute(
            request=request,
            integration_slug=integration_slug,
            operation_slug=operation_slug,
        )

    def post(self, request, integration_slug, operation_slug):
        return self._execute(
            request=request,
            integration_slug=integration_slug,
            operation_slug=operation_slug,
        )

    def _execute(self, *, request, integration_slug, operation_slug):
        # ---------------------------------------------------------
        # 1. Resolve o endpoint técnico pelo método + caminho.
        #    Não filtramos enabled aqui porque precisamos distinguir:
        #      - endpoint inexistente -> 404
        #      - endpoint existente, mas desabilitado -> 403
        # ---------------------------------------------------------
        try:
            endpoint = TechnicalEndpoint.objects.get(
                http_method=request.method,
                path=request.path,
            )
        except TechnicalEndpoint.DoesNotExist:
            return Response(
                {"detail": "Endpoint técnico não encontrado."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # ---------------------------------------------------------
        # 2. Endpoint existente, mas desabilitado.
        # ---------------------------------------------------------
        if not endpoint.enabled:
            return Response(
                {"detail": "O endpoint técnico está desabilitado."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # ---------------------------------------------------------
        # 3. A autenticação já garantiu que request.user é um
        #    ServiceCredential válido.
        # ---------------------------------------------------------
        service = request.user.service

        # ---------------------------------------------------------
        # 4. Verifica autorização do serviço para o endpoint.
        # ---------------------------------------------------------
        if not TechnicalEndpointAuthorizationService.is_authorized(
            service=service,
            endpoint=endpoint,
        ):
            return Response(
                {
                    "detail": (
                        "O serviço não está autorizado a acessar "
                        "este endpoint."
                    )
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # ---------------------------------------------------------
        # 5. Resolve a Integration configurada no Admin.
        # ---------------------------------------------------------
        try:
            integration = Integration.objects.get(
                slug=integration_slug,
                enabled=True,
            )
        except Integration.DoesNotExist:
            return Response(
                {"detail": "Integração não encontrada."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # ---------------------------------------------------------
        # 6. Resolve a operação configurada no Admin.
        # ---------------------------------------------------------
        try:
            operation = IntegrationOperation.objects.get(
                integration=integration,
                slug=operation_slug,
                enabled=True,
            )
        except IntegrationOperation.DoesNotExist:
            return Response(
                {"detail": "Operação de integração não encontrada."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # ---------------------------------------------------------
        # 7. Executa o Gateway.
        # ---------------------------------------------------------
        parameters = {}

        if request.method == "GET":
            parameters = request.query_params.dict()

        elif request.method == "POST":
            parameters = request.data

        try:
            result = IntegrationGateway(integration).execute(
                operation=operation,
                parameters=parameters,
                subject=f"service:{service.id}",
            )
        except Exception as exc:
            return Response(
                {"detail": str(exc)},
                status=status.HTTP_502_BAD_GATEWAY,
            )

        return Response(
            result,
            status=status.HTTP_200_OK,
        )