from rest_framework.permissions import BasePermission

from apps.accounts.models import User
from apps.security.models import ServiceCredential


class IsIntegrationConsumerAuthenticated(BasePermission):
    message = "É necessária uma autenticação válida."

    def has_permission(self, request, view):
        return isinstance(
            request.user,
            (User, ServiceCredential),
        )
