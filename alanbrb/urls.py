from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/accounts/', include('apps.accounts.urls')),
    path('api/v1/leads/', include('apps.leads.urls')),
    path('api/v1/conversations/', include('apps.conversations.urls')),
    path('api/v1/appointments/', include('apps.appointments.urls')),
    path('api/v1/integrations/', include('apps.integrations.urls')),
    path('api/v1/subscriptions/', include('apps.subscriptions.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)