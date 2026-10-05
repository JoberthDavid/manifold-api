from django.contrib import admin
from django.urls import path

from apps.integrations.admin_views import create_credential
from apps.integrations.models import (
    Integration,
    IntegrationCredential,
)


class IntegrationCredentialInline(admin.TabularInline):
    model = IntegrationCredential
    extra = 0

    fields = (
        "name",
        "credential_type",
        "enabled",
        "expires_at",
        "created_at",
        "updated_at",
    )

    readonly_fields = fields
    can_delete = False
    show_change_link = False

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    list_display = (
        "code",
        "name",
        "integration_type",
        "base_url",
        "enabled",
        "timeout",
    )

    search_fields = (
        "code",
        "name",
    )

    list_filter = (
        "integration_type",
        "enabled",
    )

    inlines = (
        IntegrationCredentialInline,
    )

    change_form_template = (
        "admin/integrations/integration/change_form.html"
    )

    def get_urls(self):
        urls = super().get_urls()

        custom_urls = [
            path(
                "<uuid:integration_id>/credentials/add/",
                self.admin_site.admin_view(create_credential),
                name="integrations_integration_credential_add",
            ),
        ]

        return custom_urls + urls


@admin.register(IntegrationCredential)
class IntegrationCredentialAdmin(admin.ModelAdmin):
    list_display = (
        "integration",
        "name",
        "credential_type",
        "enabled",
        "expires_at",
    )

    list_filter = (
        "credential_type",
        "enabled",
    )

    search_fields = (
        "integration__code",
        "integration__name",
        "name",
    )

    exclude = (
        "encrypted_value",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False