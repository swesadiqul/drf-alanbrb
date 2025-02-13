from rest_framework import serializers
from .models import *
from django.utils import timezone
from datetime import timedelta
from django.db import transaction
from apps.accounts.serializers import UserSerializer



# Create your serializers here
class PackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Package
        fields = ['id', 'name', 'price', 'stripe_price_id', 'interval', 'features']

    

class SubscriptionSerializer(serializers.ModelSerializer):
    package = PackageSerializer()
    user = UserSerializer() # Nested serializer

    
    class Meta:
        model = Subscription
        fields = ['id', 'user', 'package', 'start_date', 'expire_date', 'is_active']


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['id', 'user', 'subscription', 'amount', 'date', 'payment_method', 'status', 'payment_intent_id', 'charge_id']


class CheckoutSerializer(serializers.Serializer):
    stripe_price_id = serializers.CharField(required=True)

    def calculate_expire_date(self, package):
        now = timezone.now()
        if package.interval == 'monthly':
            return now + timedelta(days=30)
        elif package.interval == 'yearly':
            return now + timedelta(days=365)
        else:
            raise ValueError("Invalid interval in package.")

    def create_or_update_subscription(self, user, package):
        with transaction.atomic():
            existing_subscription = Subscription.objects.filter(user=user).first()

            if existing_subscription:
                # Update existing subscription (assuming upgrade/downgrade)
                existing_subscription.package = package
                existing_subscription.expire_date = self.calculate_expire_date(package)
                existing_subscription.save()
                return existing_subscription
            else:
                # Create a new subscription
                subscription = Subscription.objects.create(
                    user=user,
                    package=package,
                    start_date=timezone.now(),
                    expire_date=self.calculate_expire_date(package)
                )
                return subscription
            

class SubscriptionCancelSerializer(serializers.Serializer):
    subscription_id = serializers.CharField()  # Accepts ID as a string

    def cancel_subscription(self):
        subscription_id = self.validated_data.get("subscription_id")

        # Attempt to fetch the subscription instance
        try:
            subscription = Subscription.objects.get(id=subscription_id)
        except Subscription.DoesNotExist:
            raise serializers.ValidationError("Subscription with this ID does not exist.")

        # Update the subscription fields
        subscription.is_active = False
        subscription.expire_date = timezone.now()
        subscription.save()

        return subscription