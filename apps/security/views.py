from __future__ import annotations

from django.http import JsonResponse
from django.views.decorators.http import require_GET

from apps.security.services.jwt_jwks import JwtJwksService


@require_GET
def jwks_view(request):
    """
    Publica as chaves públicas utilizadas pelo Manifold
    para assinatura de JWTs.
    """
    return JsonResponse(JwtJwksService.build())