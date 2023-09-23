from drf_spectacular.utils import extend_schema_serializer
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from backend.models import Address, User


class StatusTrueSerializer(serializers.Serializer):
    Status = serializers.BooleanField()


class StatusFalseSerializer(serializers.Serializer):
    Status = serializers.BooleanField()
    Errors = serializers.CharField()


class AddressSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        # Don't pass the 'user_id' arg up to the superclass
        user_id = kwargs.pop("user_id", None)

        # Instantiate the superclass normally
        super().__init__(*args, **kwargs)

        if user_id and kwargs.get("data"):
            self.initial_data["user"] = user_id

    def validate(self, attrs):
        MAX_ADDRESS_COUNT = 5
        address_count = Address.objects.filter(
            user_id=self.initial_data["user"]
        ).count()
        if address_count >= MAX_ADDRESS_COUNT:
            raise ValidationError(
                # TODO change error message?
                f"Максимальное количество адресов: {MAX_ADDRESS_COUNT}."
            )
        return attrs

    class Meta:
        model = Address
        fields = [
            "id",
            "user",
            "city",
            "street",
            "house",
            "structure",
            "building",
            "apartment",
        ]
        read_only_fields = ["id"]
        extra_kwargs = {"user": {"write_only": True}}


@extend_schema_serializer(exclude_fields=["address"])
class UserSerializer(serializers.ModelSerializer):
    address = AddressSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "last_name",
            "first_name",
            "patronymic",
            "company",
            "position",
            "phone",
            "address",
        ]
        read_only_fields = ["id"]


class UserWithPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = [
            "email",
            "password",
            "last_name",
            "first_name",
            "patronymic",
            "company",
            "position",
            "phone",
        ]
