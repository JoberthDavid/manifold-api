from django import forms

from apps.integrations.models import CredentialType


class IntegrationCredentialForm(forms.Form):
    name = forms.CharField(
        label="Nome",
        max_length=200,
    )
    credential_type = forms.ChoiceField(
        label="Tipo",
        choices=CredentialType.choices,
    )
    secret = forms.CharField(
        label="Segredo",
        widget=forms.PasswordInput(
            render_value=False,
        ),
        strip=False,
        required=True,
    )
    expires_at = forms.DateTimeField(
        label="Expira em",
        required=False,
        widget=forms.DateTimeInput(
            attrs={"type": "datetime-local"},
        ),
    )
    enabled = forms.BooleanField(
        label="Ativa",
        required=False,
        initial=True,
    )
    