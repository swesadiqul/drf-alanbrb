from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from .managers import UserManager
from .permissions import has_permission


class User(AbstractBaseUser, PermissionsMixin):
    class Role(models.TextChoices):
        SUPER_ADMIN = 'SA', 'Super Admin'
        ADMIN = 'AD', 'Admin'
        AI = 'AI', 'AI Assistant'

    name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    image = models.ImageField(upload_to="users/", default="users/avatar.png")
    bio = models.TextField(null=True, blank=True)

    # Role and permissions
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, null=True, blank=True, editable=False)
    otp_expiry = models.DateTimeField(null=True, blank=True, editable=False)

    # Timestamps
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)

    role = models.CharField(max_length=2, choices=Role.choices, default=Role.ADMIN)

    # Manager
    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    def is_otp_expired(self):
        """Check if the OTP has expired."""
        if self.otp_expiry:
            return timezone.now() > self.otp_expiry
        return False

    def __str__(self):
        return f"{self.name} ({self.get_role_display()})"

    def has_permission(self, permission_codename):
        """Check if the user has a specific permission."""
        return has_permission(self, permission_codename)

    # Override save method to set is_staff based on role
    def save(self, *args, **kwargs):
        if self.role == self.Role.SUPER_ADMIN:
            self.is_staff = True
            self.is_superuser = True
        elif self.role == self.Role.ADMIN:
            self.is_staff = True
            self.is_superuser = False
        elif self.role == self.Role.AI:
            self.is_staff = False
            self.is_superuser = False

        super().save(*args, **kwargs)
