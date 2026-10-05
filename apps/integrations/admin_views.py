from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from apps.integrations.admin_forms import IntegrationCredentialForm
from apps.integrations.models import Integration
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


@staff_member_required
def create_credential(request, integration_id):
    integration = get_object_or_404(
        Integration,
        id=integration_id,
    )

    if request.method == "POST":
        form = IntegrationCredentialForm(request.POST)

        if form.is_valid():
            credential = IntegrationCredentialService.create(
                integration=integration,
                name=form.cleaned_data["name"],
                credential_type=form.cleaned_data["credential_type"],
                secret=form.cleaned_data["secret"],
                expires_at=form.cleaned_data["expires_at"],
            )

            if not form.cleaned_data["enabled"]:
                IntegrationCredentialService.disable(credential)

            messages.success(
                request,
                "Credencial criada com sucesso.",
            )

            return redirect(
                reverse(
                    "admin:integrations_integration_change",
                    args=[integration.id],
                )
            )
    else:
        form = IntegrationCredentialForm()

    return render(
        request,
        "admin/integrations/integrationcredential_form.html",
        {
            "form": form,
            "integration": integration,
            "title": "Adicionar credencial",
        },
    )