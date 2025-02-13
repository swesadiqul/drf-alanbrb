from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.timezone import now
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=User.Role.choices, default=User.Role.ADMIN)

    class Meta:
        model = User
        fields = ['name', 'email', 'role', 'password']

    def validate_role(self, value):
        """Ensure only Super Admins can create other Super Admins."""
        request = self.context.get("request")
        if request and request.user.is_authenticated:
            if value == User.Role.SUPER_ADMIN and not request.user.is_super_admin():
                raise serializers.ValidationError("Only Super Admins can create another Super Admin.")
        else:
            # In case there's no authenticated user (e.g., anonymous user)
            if value == User.Role.SUPER_ADMIN:
                raise serializers.ValidationError("Only authenticated Super Admins can create another Super Admin.")
        return value

    def create(self, validated_data):
        """Create a new user with the specified role and hashed password."""
        user = User.objects.create_user(**validated_data)
        return user

        

class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ['email']
    
    def validate_email(self, email):
        email = email.lower()
        if not User.objects.filter(email=email).exists():
            raise ValidationError("The provided email does not exist.")
        return email
    

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()

    class Meta:
        fields = ['email', 'otp']
    
    def validate_email(self, email):
        email = email.lower()
        if not User.objects.filter(email=email).exists():
            raise ValidationError("The provided email does not exist.")
        return email
    
    def validate(self, data):
        email = data.get('email').lower()
        otp = data.get('otp')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise ValidationError({"email": "User does not exist."})

        # Check if the OTP matches
        if user.otp != otp:
            raise ValidationError({"otp": "Invalid OTP."})

        # Check if OTP is expired
        if user.otp_expiry and now() > user.otp_expiry:
            raise ValidationError({"otp": "OTP has expired. Please request a new one."})

        return data


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, style={'input_type': 'password'})

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email:
            raise ValidationError({"email": "Email is required."})
        if not password:
            raise ValidationError({"password": "Password is required."})

        # Use Django's authenticate function
        user = authenticate(request=self.context.get('request'), username=email, password=password)

        if user is None:
            raise ValidationError({"message": "Invalid email or password."})
        
        # If authentication is successful, add user to the validated data
        data['user'] = user
        return data
       
class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate(self, attrs):
        refresh_token = attrs.get('refresh_token')

        if not refresh_token:
            raise ValidationError({"refresh_token": "Refresh token is required."})

        try:
            RefreshToken(refresh_token)
        except TokenError:
            raise ValidationError({"refresh_token": "Token is invalid or expired."})

        return attrs

    def save(self, **kwargs):
        RefreshToken(self.validated_data['refresh_token']).blacklist()
        return True

    

class UserSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=False)

    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'bio', 'role', "image", 'date_joined', 'last_login']
        # fields = '__all__'
        # read_only_fields = ['id', 'email', 'date_joined', 'last_login']

    def get_image(self, obj):
        request = self.context.get('request')
        if obj.image and request:
            return request.build_absolute_uri(obj.image.url)
        return None
    

class ChangePasswordSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['old_password', 'new_password', 'confirm_password']
    

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise ValidationError("Passwords do not match.")
        return data


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ['email']
    
    def validate_email(self, email):
        email = email.lower()
        if not User.objects.filter(email=email).exists():
            raise ValidationError("The provided email does not exist.")
        return email
    

class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()
    

    class Meta:
        fields = ['email', 'new_password', 'confirm_password']


    def validate_email(self, email):
        email = email.lower()
        if not User.objects.filter(email=email).exists():
            raise ValidationError("The provided email does not exist.")
        return email
    

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise ValidationError("Passwords do not match.")
        return data
    

class EmailVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    class Meta:
        fields = ['email', 'otp']
    
    def validate(self, attrs):
        email = attrs.get('email').lower()
        otp = attrs.get('otp')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise ValidationError({"email": "User does not exist."})
        

        # Check if the OTP matches
        if user.otp != otp:
            raise ValidationError({"otp": "Invalid OTP."})
        
        # Check if OTP is expired
        if user.otp_expiry and now() > user.otp_expiry:
            raise ValidationError({"otp": "OTP has expired. Please request a new one."})
        
        return attrs




