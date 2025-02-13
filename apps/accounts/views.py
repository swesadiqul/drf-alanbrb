from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import *
from rest_framework_simplejwt.authentication import JWTAuthentication
from .utils import *
from django.utils import timezone
from datetime import timedelta


# Create your views here.
class RegistrationView(APIView):
    serializer_class = RegistrationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            name = serializer.validated_data.get('name')
            user = serializer.save()
            
            otp = send_email([email], name)
            if otp:
                user.otp = otp
                user.otp_expiry = now() + timedelta(minutes=2)
                user.save()
                return Response(
                    {
                        "status": "success",
                        "message": "User registered successfully.",
                        "code": status.HTTP_201_CREATED,
                        "data": serializer.data,
                    },
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {
                        "status": "error",
                        "message": "Failed to send OTP.",
                        "code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        return Response(
            {
                "status": "error",
                "message": "Invalid input data.",
                "code": status.HTTP_400_BAD_REQUEST,
                "detail": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class SendOTPView(APIView):
    serializer_class = SendOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            try:
                user = User.objects.get(email=email)
                if not user.is_active:
                    return Response({"status": "error", "message": "Account is inactive."}, status=status.HTTP_400_BAD_REQUEST)

                # Generate and send OTP
                user.otp = send_email([email], user.name)
                user.otp_expiry = timezone.now() + timedelta(minutes=2)
                user.save()

                return Response(
                    {
                        "status": "success", 
                        "code": status.HTTP_200_OK,
                        "message": "OTP sent successfully!"
                    },
                    status=status.HTTP_200_OK,
                )
            except User.DoesNotExist:
                return Response(
                    {
                        "status": "error", 
                        "code": status.HTTP_404_NOT_FOUND,
                        "message": "User with this email does not exist."
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )

        return Response(
            {
                "status": "error", 
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Invalid email.", 
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class VerifyOTPView(APIView):
    serializer_class = VerifyOTPSerializer


    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            otp = serializer.validated_data.get('otp')
            user = User.objects.get(email=email)
            # Verify OTP
            if user.otp == otp:
                if user.otp_expiry and now() > user.otp_expiry:
                    return Response(
                        {
                            "status": "error", 
                            "code": status.HTTP_400_BAD_REQUEST,
                            "message": "OTP has expired. Please request a new one."
                        },
                        status=status.HTTP_400_BAD_REQUEST)
                
                return Response(
                    {
                        "status": "success", 
                        "code": status.HTTP_200_OK,
                        "message": "OTP verified successfully."
                    },
                    status=status.HTTP_200_OK)
            
            return Response(
                {
                    "status": "error", 
                    "code": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid OTP."
                },
                status=status.HTTP_400_BAD_REQUEST)
        return Response(
            {
                "status": "error", 
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Invalid input data.", 
                "detail": serializer.errors
            }, 
            status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            user = serializer.validated_data.get('user')
            token = get_tokens_for_user(user)
            user.last_login = now()
            user.save()

            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": "User logged in successfully.",
                    "data": {
                        "access_token": token.get('access_token'),
                        "refresh_token": token.get('refresh_token')
                    }
                },
                status=status.HTTP_200_OK
            )
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Invalid credentials.",
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": "User logged out successfully.",
                    "data": None
                },
                status=status.HTTP_200_OK
            )
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Token is invalid or expired.",
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )


class ChangePasswordView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        user = request.user
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            old_password = serializer.validated_data.get('old_password')
            new_password = serializer.validated_data.get('new_password')
            if not user.check_password(old_password):
                return Response(
                    {
                        "status": "error",
                        "code": status.HTTP_400_BAD_REQUEST,
                        "message": "Invalid old password.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user.set_password(new_password)
            user.save()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": "Password changed successfully.",
                },
                status=status.HTTP_200_OK,
            )
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Invalid input data.",
                "detail": serializer.errors,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class PasswordResetView(APIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            try:
                user = User.objects.get(email=email)
                user.otp = send_email([email], user.name)
                user.otp_expiry = now() + timedelta(minutes=2)
                user.save()
                return Response(
                    {
                        "status": "success",
                        "code": status.HTTP_200_OK,
                        "message": "OTP sent successfully!"
                    },
                    status=status.HTTP_200_OK
                )
            except User.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "code": status.HTTP_404_NOT_FOUND,
                        "message": "No account found with the provided email."
                    },
                    status=status.HTTP_404_NOT_FOUND
                )
        return Response(
            {
                "status": "error",
                "message": "Invalid email address provided.",
                "code": status.HTTP_400_BAD_REQUEST,
                "errors": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )


class PasswordResetConfirmView(APIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            try:
                user = User.objects.get(email=email)
                new_password = serializer.validated_data.get('new_password')
                user.set_password(new_password)
                user.save()
                return Response(
                    {
                        "status": "success",
                        "code": status.HTTP_200_OK,
                        "message": "Password reset successfully."
                    },
                    status=status.HTTP_200_OK
                )
            except User.DoesNotExist:
                return Response(
                    {
                        "status": "error",
                        "code": status.HTTP_404_NOT_FOUND,
                        "message": "No account found with the provided email."
                    },
                    status=status.HTTP_404_NOT_FOUND
                )
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Invalid data provided for password reset.",
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    

class UserListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get(self, request):
        # users = User.objects.get(id=request.user.id)
        users = User.objects.all()
        serializer = self.serializer_class(users, context={'request': request}, many = True)
        return Response(
            {
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "Users retrieved successfully.",
                "data": serializer.data
            },
            status=status.HTTP_200_OK)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_201_CREATED,
                    "message": "User created successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_201_CREATED)
        return Response(
            {
                "status": "error",
                "code": status.HTTP_400_BAD_REQUEST,
                "message": "Invalid input data.",
                "detail": serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get(self, request):
        try:
            user = request.user
            serializer = self.serializer_class(user, context={'request': request})
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": f"User with ID {user.id} retrieved successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return Response(
                {
                    "status": "error",
                    "code": status.HTTP_404_NOT_FOUND,
                    "message": f"User does not exist.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )




class UserDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer

    def get(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            serializer = self.serializer_class(user, context={'request': request})
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": f"User with ID {pk} retrieved successfully.",
                    "data": serializer.data
                },
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return Response(
                {
                    "status": "error",
                    "code": status.HTTP_404_NOT_FOUND,
                    "message": f"User with ID {pk} does not exist.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

    def patch(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            serializer = self.serializer_class(user, data=request.data, partial=True, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response(
                    {
                        "status": "success",
                        "code": status.HTTP_200_OK,
                        "message": f"User with ID {pk} updated successfully.",
                        "data": serializer.data
                    },
                    status=status.HTTP_200_OK,
                )
            return Response(
                {
                    "status": "error",
                    "code": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data provided for updating the user.",
                    "detail": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except User.DoesNotExist:
            return Response(
                {
                    "status": "error",
                    "code": status.HTTP_404_NOT_FOUND,
                    "message": f"User with ID {pk} does not exist.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )

    def delete(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            return Response(
                {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": f"User with ID {pk} deleted successfully.",
                },
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return Response(
                {
                    "status": "error",
                    "code": status.HTTP_404_NOT_FOUND,
                    "message": f"User with ID {pk} does not exist.",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
