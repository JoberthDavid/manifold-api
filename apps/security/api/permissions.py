from rest_framework.permissions import BasePermission

from apps.security.models import ServiceCredential


class IsServiceAuthenticated(BasePermission):
    message = "É necessária uma credencial de serviço válida."

    def has_permission(self, request, view):
        return isinstance(request.user, ServiceCredential)