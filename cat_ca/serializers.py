from rest_framework import serializers

__all__ = [
    "CATVerificationKeyInputSerializer",
    "CATVerificationKeyOutputSerializer",
    "CATCreationKeyInputSerializer",
    "CATCreationKeyOutputSerializer",
]


class CATVerificationKeyInputSerializer(serializers.Serializer):
    type = serializers.CharField(max_length=255)  # noqa: A003
    name = serializers.CharField(max_length=255)


class CATVerificationKeyOutputSerializer(serializers.Serializer):
    verification_key = serializers.CharField()


class CATCreationKeyInputSerializer(serializers.Serializer):
    service = serializers.CharField(max_length=255)


class CATCreationKeyOutputSerializer(serializers.Serializer):
    creation_key = serializers.CharField()
