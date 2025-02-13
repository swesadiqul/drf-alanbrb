from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .serializers import *
from .models import *
from rest_framework.exceptions import NotFound
from django.conf import settings
from django.http.response import JsonResponse
import stripe
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.shortcuts import redirect



# Create your views here.
class PackageListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = PackageSerializer

    def get(self, request):
        package = Package.objects.all()
        serializer = self.serializer_class(package, many=True)
        return Response(
            {
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "Packages retrieved successfully.",
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            package = serializer.save()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_201_CREATED,
                    "message": "Package created successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_201_CREATED
            )
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Bad request.",
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )


class PackageDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = PackageSerializer

    def _get_package(self, pk):
        try:
            return Package.objects.get(pk=pk)
        except Package.DoesNotExist:
            raise NotFound(detail="Package not found")


    def get(self, request, pk):
        package = self._get_package(pk)
        serializer = self.serializer_class(package)
        return Response(
            {
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "Package details retrieved successfully.",
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )


    def put(self, request, pk):
        package = self._get_package(pk)
        serializer = self.serializer_class(package, data=request.data)
        if serializer.is_valid():
            package = serializer.save()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": "Package updated successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Bad request.",
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )

    def patch(self, request, pk):
        package = self._get_package(pk)
        serializer = self.serializer_class(package, data=request.data, partial=True)
        if serializer.is_valid():
            package = serializer.save()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": "Package partially updated successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )
        return Response(
            {
                "status": "error",
                "message": "Bad request.",
                "code": status.HTTP_400_BAD_REQUEST,
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )

    def delete(self, request, pk):
        package = self._get_package(pk)
        package.delete()
        return Response(
            {
                "status": "success",
                "code": status.HTTP_204_NO_CONTENT,
                "message": "Package deleted successfully.",
            },
            status=status.HTTP_204_NO_CONTENT
        )


class SubscriptionListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = SubscriptionSerializer

    # def get(self, request):
    #     subscriptions = Subscription.objects.all()
    #     serializer = self.serializer_class(subscriptions, many=True)
    #     return Response(
    #         {
    #             "status": "success",
    #             "code": status.HTTP_200_OK,
    #             "message": "Subscriptions retrieved successfully.",
    #             "data": serializer.data
    #         },
    #         status=status.HTTP_200_OK
    #     )
    
    def get(self, request):
        subscriptions = Subscription.objects.get(user=request.user)
        serializer = self.serializer_class(subscriptions)
        return Response(
            {
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "Subscriptions retrieved successfully.",
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            subscription = serializer.save()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_201_CREATED,
                    "message": "Subscription created successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_201_CREATED
            )
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Bad request.",
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )


class SubscriptionDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = SubscriptionSerializer

    def _get_subscription(self, pk):
        try:
            return Subscription.objects.get(pk=pk)
        except Subscription.DoesNotExist:
            raise NotFound(detail="Subscription not found")

    def get(self, request, pk):
        subscription = self._get_subscription(pk)
        serializer = self.serializer_class(subscription)
        return Response(
            {
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "Subscription details retrieved successfully.",
                "data": serializer.data
            },
            status=status.HTTP_200_OK
        )

    def put(self, request, pk):
        subscription = self._get_subscription(pk)
        serializer = self.serializer_class(subscription, data=request.data)
        if serializer.is_valid():
            subscription = serializer.save()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": "Subscription updated successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK
            )
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Bad request.",
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )


    def patch(self, request, pk):
        subscription = self._get_subscription(pk)
        serializer = self.serializer_class(subscription, data=request.data, partial=True)
        if serializer.is_valid():
            subscription = serializer.save()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": "Subscription partially updated successfully.",
                    "data": serializer.data
                }, 
                status=status.HTTP_200_OK
            )
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Bad request.",
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )


    def delete(self, request, pk):
        subscription = self._get_subscription(pk)
        subscription.delete()
        return Response(
            {
                "status": "success",
                "code": status.HTTP_204_NO_CONTENT,
                "message": "Subscription deleted successfully."
            }, 
            status=status.HTTP_204_NO_CONTENT
        )



# Configure Stripe API key

stripe.api_key = settings.STRIPE_SECRET_KEY

class CheckoutSessionView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = CheckoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = request.user

            # Get the stripe_price_id from the validated data
            stripe_price_id = serializer.validated_data['stripe_price_id']

            try:
                # Retrieve the Package object based on stripe_price_id
                package = Package.objects.get(stripe_price_id=stripe_price_id)
            except Package.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "code": status.HTTP_400_BAD_REQUEST,
                        "message": "Subscription package not found."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create or update the subscription for the user
            subscription = serializer.create_or_update_subscription(user, package)

            # Create the Stripe checkout session
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                client_reference_id=user.pk,
                line_items = [
                    {
                        'price': package.stripe_price_id,
                        'quantity': 1,
                    },
                ],
                mode='subscription',
                subscription_data={
                    'trial_period_days': 7,  # 7-day free trial
                },
                success_url='https://cb31-115-127-156-9.ngrok-free.app/api/v1/success/',
                cancel_url='https://cb31-115-127-156-9.ngrok-free.app/api/v1/cancel/',
            )

            return JsonResponse({
                "status": "success",
                "code": status.HTTP_102_PROCESSING,
                "message": "Subscription pending. Complete payment to activate.",
                "data": checkout_session.url
            })

        return Response({
            "status": "error",
            "message": "Invalid input data.",
            "detail": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
        

class StripeWebhookView(APIView):
    def post(self, request, *args, **kwargs):
        payload = request.body
        sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
        except ValueError:
            return Response({"error": "Invalid payload"}, status=status.HTTP_400_BAD_REQUEST)
        except stripe.error.SignatureVerificationError:
            return Response({"error": "Invalid signature"}, status=status.HTTP_400_BAD_REQUEST)

        if event["type"] == "checkout.session.completed":
            session = event["data"]["object"]
            response = subscription_update(session)
            print("===========: ", response)

        if event["type"] == "payment_intent.succeeded":
            session = event["data"]["object"]
            print("Successed==========: ", session)
            subscription_renew(session)

        elif event["type"] == "payment_intent.payment_failed":
            session = event["data"]["object"]
            print("Failed==========: ", session)
            subscription_cancel(session)

        return Response({"status": "success", "message": "Webhook is successfully called!", "code": status.HTTP_200_OK}, status=status.HTTP_200_OK)
    

class SubscriptionCancelView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = SubscriptionCancelSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(
                {
                    "status": "error",
                    "code": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data provided.",
                    "detail": serializer.errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            subscription = serializer.cancel_subscription()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": "Subscription has been canceled.",
                    "data": {"user_email": subscription.user.email},
                },
                status=status.HTTP_200_OK,
            )
        except serializers.ValidationError as e:
            return Response(
                {
                    "status": "error",
                    "code": status.HTTP_400_BAD_REQUEST,
                    "message": "Validation error occurred.",
                    "detail": e.detail if hasattr(e, "detail") else str(e),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {
                    "status": "error",
                    "code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "message": "An error occurred while canceling the subscription.",
                    "detail": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
    

class SuccessView(APIView):
    def get(self, request, *args, **kwargs):
        # After successful payment, redirect to the payment success page
        return redirect("http://localhost:5173/paymentSuccess")


class CancelView(APIView):
    def get(self, request, *args, **kwargs):
        return redirect("http://localhost:5173/paymentCancel")
