from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.authentication import (
    AuthenticationService,
    AuthenticationStatus,
)

from .serializers import (
    AuthenticationResponseSerializer,
    LoginSerializer,
    TwoFactorVerifySerializer,
)


class AuthenticationResponseMixin:
    STATUS_HTTP_MAPPING = {
        AuthenticationStatus.INVALID_CREDENTIALS: status.HTTP_401_UNAUTHORIZED,
        AuthenticationStatus.INACTIVE_USER: status.HTTP_403_FORBIDDEN,
        AuthenticationStatus.TWO_FACTOR_REQUIRED: status.HTTP_200_OK,
        AuthenticationStatus.TWO_FACTOR_INVALID_CODE: status.HTTP_400_BAD_REQUEST,
        AuthenticationStatus.TWO_FACTOR_EXPIRED: status.HTTP_400_BAD_REQUEST,
        AuthenticationStatus.TWO_FACTOR_EXHAUSTED: status.HTTP_400_BAD_REQUEST,
        AuthenticationStatus.TWO_FACTOR_REVOKED: status.HTTP_400_BAD_REQUEST,
        AuthenticationStatus.EMAIL_DELIVERY_FAILED: (
            status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        AuthenticationStatus.AUTHENTICATED: status.HTTP_200_OK,
    }

    @classmethod
    def _build_response(cls, result):
        data = {
            "status": result.status.value,
            "challenge_id": result.challenge_id,
            "attempts_remaining": result.attempts_remaining,
            "token": result.token,
        }

        serializer = AuthenticationResponseSerializer(data=data)
        serializer.is_valid(raise_exception=True)

        http_status = cls.STATUS_HTTP_MAPPING.get(
            result.status,
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

        return Response(
            serializer.data,
            status=http_status,
        )


class LoginView(AuthenticationResponseMixin, APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        result = AuthenticationService.login(
            email=serializer.validated_data["email"],
            password=serializer.validated_data["password"],
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
        )

        return self._build_response(result)


class TwoFactorVerifyView(AuthenticationResponseMixin, APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TwoFactorVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        result = AuthenticationService.verify_two_factor(
            challenge_id=serializer.validated_data["challenge_id"],
            code=serializer.validated_data["code"],
            ip_address=request.META.get("REMOTE_ADDR"),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
        )

        return self._build_response(result)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        token = request.auth

        if not token:
            return Response(
                {"detail": "Sessão inválida."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        revoked = AuthenticationService.logout(token)

        if not revoked:
            return Response(
                {"detail": "Sessão inválida."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        return Response(
            {"status": "LOGGED_OUT"},
            status=status.HTTP_200_OK,
        )


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        return Response(
            {
                "id": str(user.id),
                "email": user.email,
                "is_active": user.is_active,
            },
            status=status.HTTP_200_OK,
        )
