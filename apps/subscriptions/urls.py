from django.urls import path
from .views import *



# Create your urlpatterns here
urlpatterns = [
    path('packages/', PackageListView.as_view(), name='package_list'),
    path('packages/<int:pk>/', PackageDetailView.as_view(), name='package_detail'),

    # Subscriptions
    path('subscriptions/', SubscriptionListView.as_view(), name='subscription_list_create'),
    path('subscriptions/<int:pk>/', SubscriptionDetailView.as_view(), name='subscription_detail'),
    path('subscriptions/cancel/', SubscriptionCancelView.as_view(), name="subscription_cancel"),

    # Payments
    path('checkout-session/', CheckoutSessionView.as_view(), name='subscription'),
    path('stripe-webhook/', StripeWebhookView.as_view(), name='stripe_webhook'),
    path('success/', SuccessView.as_view(), name='success'),
    path('cancel/', CancelView.as_view(), name='cancel'),
]