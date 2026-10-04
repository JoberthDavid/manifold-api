from rest_framework import serializers


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
    )


class TwoFactorVerifySerializer(serializers.Serializer):
    challenge_id = serializers.UUIDField()
    code = serializers.CharField(
        min_length=6,
        max_length=6,
        trim_whitespace=False,
        write_only=True,
    )


class AuthenticationResponseSerializer(serializers.Serializer):
    status = serializers.CharField()
    challenge_id = serializers.CharField(
        allow_null=True,
        required=False,
    )
    attempts_remaining = serializers.IntegerField(
        allow_null=True,
        required=False,
    )
    token = serializers.CharField(
        allow_null=True,
        required=False,
    )