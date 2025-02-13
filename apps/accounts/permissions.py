from django.contrib.auth.models import Permission


ROLE_PERMISSIONS = {
    "SA": [
        "view_all_users", "manage_clients", "view_leads", 
        "generate_reports", "manage_security", "full_access"
    ],
    "AD": [
        "view_own_leads", "manage_integrations", 
        "supervise_ai", "access_own_data"
    ],
    "AI": [
        "send_messages", "book_appointments", 
        "store_conversations", "handle_queries"
    ],
}

def has_permission(user, permission_codename):
    """Check if a user has a specific permission based on their role."""
    return permission_codename in ROLE_PERMISSIONS.get(user.role, [])

def get_role_permissions(user):
    """Return a set of permissions based on the user's role."""
    return Permission.objects.filter(codename__in=ROLE_PERMISSIONS.get(user.role, []))
