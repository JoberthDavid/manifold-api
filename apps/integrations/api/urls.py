from django.urls import path

from .views import IntegrationExecuteView


app_name = "integrations-api"

urlpatterns = [
    path(
        "<slug:integration_slug>/<slug:operation_slug>/",
        IntegrationExecuteView.as_view(),
        name="execute",
    ),
]