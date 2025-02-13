from django.contrib.auth.models import BaseUserManager

class UserManager(BaseUserManager):
    def create_user(self, email, name, role, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        if not name:
            raise ValueError("The Name field must be set")
        if role not in ["SA", "AD", "AI"]:
            raise ValueError("Invalid role assigned")

        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, name=name, role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault("role", "SA")
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if not extra_fields.get("is_staff"):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, name, "SA", password, **extra_fields)
