from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/accounts/', include('apps.accounts.urls')),
    path('api/leads/', include('apps.leads.urls')),
    path('api/conversations/', include('apps.conversations.urls')),
    path('api/appointments/', include('apps.appointments.urls')),
    path('api/integrations/', include('apps.integrations.urls')),
    path('api/subscriptions/', include('apps.subscriptions.urls')),
]