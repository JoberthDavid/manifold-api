from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.integrations.gateway import IntegrationGateway
from apps.integrations.models import Integration, IntegrationOperation
from apps.integrations.api.authentication import IntegrationRequestAuthentication
from apps.integrations.api.permissions import IsIntegrationConsumerAuthenticated
from apps.security.services.technical_endpoint_authorization import TechnicalEndpointAuthorizationService
from apps.accounts.models import User
from apps.security.models import (
    ServiceCredential,
    TechnicalEndpoint,
)


class IntegrationExecuteView(APIView):
    authentication_classes = (IntegrationRequestAuthentication,)
    permission_classes = (IsIntegrationConsumerAuthenticated,)

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

    def put(self, request, integration_slug, operation_slug):
        return self._execute(
            request=request,
            integration_slug=integration_slug,
            operation_slug=operation_slug,
        )

    def patch(self, request, integration_slug, operation_slug):
        return self._execute(
            request=request,
            integration_slug=integration_slug,
            operation_slug=operation_slug,
        )

    def delete(self, request, integration_slug, operation_slug):
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
        # 3. Autoriza o consumidor conforme o tipo de credencial.
        # ---------------------------------------------------------
        if isinstance(request.user, ServiceCredential):
            service = request.user.service

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

            subject = f"service:{service.id}"

        elif isinstance(request.user, User):
            if not request.user.is_superuser:
                return Response(
                    {
                        "detail": (
                            "O usuário não está autorizado a acessar "
                            "este endpoint."
                        )
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            subject = f"user:{request.user.id}"

        else:
            return Response(
                {"detail": "Consumidor não autorizado."},
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

        elif request.method in ("PUT", "PATCH"):
            parameters = request.data.copy()
            parameters.update(request.query_params.dict())

        elif request.method == "DELETE":
            parameters = {}

            if isinstance(request.data, dict):
                parameters.update(request.data)

            parameters.update(request.query_params.dict())

        try:
            result = IntegrationGateway(integration).execute(
                operation=operation,
                parameters=parameters,
                subject=subject,
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