from django import forms
from django.contrib import admin
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path, reverse

from .models import (
    JwtSigningKey,
    Service,
    ServiceCredential,
    TechnicalEndpoint,
    ServiceTechnicalEndpoint,
)
from .services.service_credentials import ServiceCredentialService


class ServiceCredentialAdminForm(forms.ModelForm):
    generate_token = forms.BooleanField(
        label="Gerar token de acesso",
        required=False,
        initial=True,
        help_text=(
            "Gera um token de acesso automaticamente. "
            "O token será exibido uma única vez após a criação "
            "e não poderá ser recuperado posteriormente."
        ),
    )

    class Meta:
        model = ServiceCredential
        fields = (
            "service",
            "name",
            "enabled",
            "expires_at",
            "generate_token",
        )


@admin.register(JwtSigningKey)
class JwtSigningKeyAdmin(admin.ModelAdmin):
    list_display = (
        "kid",
        "algorithm",
        "enabled",
        "retired_at",
        "created_at",
    )

    list_filter = (
        "algorithm",
        "enabled",
    )

    search_fields = (
        "kid",
    )

    readonly_fields = (
        "id",
        "kid",
        "public_key",
        "created_at",
    )

    ordering = (
        "-created_at",
    )

    fieldsets = (
        (
            "Identificação",
            {
                "fields": (
                    "id",
                    "kid",
                    "algorithm",
                )
            },
        ),
        (
            "Chaves",
            {
                "fields": (
                    "private_key",
                    "public_key",
                ),
            },
        ),
        (
            "Estado",
            {
                "fields": (
                    "enabled",
                    "retired_at",
                ),
            },
        ),
        (
            "Auditoria",
            {
                "fields": (
                    "created_at",
                ),
            },
        ),
    )


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "slug",
        "enabled",
        "created_at",
        "updated_at",
    )

    list_filter = (
        "enabled",
    )

    search_fields = (
        "name",
        "slug",
    )

    readonly_fields = (
        "id",
        "slug",
        "created_at",
        "updated_at",
    )

    ordering = (
        "name",
    )


@admin.register(ServiceCredential)
class ServiceCredentialAdmin(admin.ModelAdmin):
    form = ServiceCredentialAdminForm

    list_display = (
        "name",
        "service",
        "enabled",
        "expires_at",
        "last_used_at",
        "created_at",
    )

    list_filter = (
        "enabled",
        "service",
    )

    search_fields = (
        "name",
        "service__name",
        "service__slug",
    )

    readonly_fields = (
        "id",
        "token_hash",
        "last_used_at",
        "created_at",
    )

    autocomplete_fields = (
        "service",
    )

    ordering = (
        "service__name",
        "name",
    )

    fieldsets = (
        (
            "Credencial",
            {
                "fields": (
                    "id",
                    "service",
                    "name",
                ),
            },
        ),
        (
            "Segurança",
            {
                "fields": (
                    "token_hash",
                    "generate_token",
                    "enabled",
                    "expires_at",
                ),
                "description": (
                    "O token original não é armazenado. "
                    "Somente o hash SHA-256 é persistido."
                ),
            },
        ),
        (
            "Uso",
            {
                "fields": (
                    "last_used_at",
                ),
            },
        ),
        (
            "Auditoria",
            {
                "fields": (
                    "created_at",
                ),
            },
        ),
    )

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)

        if obj is not None:
            fieldsets = tuple(
                (
                    title,
                    {
                        **options,
                        "fields": tuple(
                            field
                            for field in options["fields"]
                            if field != "generate_token"
                        ),
                    },
                )
                for title, options in fieldsets
            )

        return fieldsets

    def save_model(self, request, obj, form, change):
        """
        Cria a ServiceCredential através do serviço de domínio.

        O plaintext do token nunca é persistido.
        Quando solicitado, ele permanece apenas no objeto request
        durante esta requisição HTTP.
        """
        if change:
            super().save_model(request, obj, form, change)
            return

        generate_token = form.cleaned_data.get(
            "generate_token",
            True,
        )

        credential, token = ServiceCredentialService.create(
            name=obj.name,
            service=obj.service,
            expires_at=obj.expires_at,
        )

        if credential.enabled != obj.enabled:
            credential.enabled = obj.enabled
            credential.save(update_fields=("enabled",))

        if generate_token:
            request._generated_service_credential_token = token

        request._created_service_credential = credential

        obj.pk = credential.pk

    def response_add(self, request, obj, post_url_continue=None):
        """
        Após a criação, exibe o token diretamente na resposta.

        O token não é colocado em:
        - banco de dados;
        - sessão;
        - URL;
        - cookie;
        - campo do model.

        Ele existe somente durante esta requisição.
        """
        token = getattr(
            request,
            "_generated_service_credential_token",
            None,
        )

        credential = getattr(
            request,
            "_created_service_credential",
            None,
        )

        if token and credential:
            return self._render_token_page(
                request=request,
                credential=credential,
                token=token,
            )

        return super().response_add(
            request,
            obj,
            post_url_continue=post_url_continue,
        )

    def _render_token_page(self, request, credential, token):
        context = {
            **self.admin_site.each_context(request),
            "title": "Token de acesso gerado",
            "credential": credential,
            "token": token,
            "opts": self.model._meta,
        }

        return TemplateResponse(
            request,
            "admin/security/servicecredential/token.html",
            context,
        )

    def get_urls(self):
        """
        Não expõe endpoint adicional para geração do token.

        Mantemos o método apenas para preservar a estrutura de URLs
        caso futuramente sejam adicionadas ações específicas.
        """
        return super().get_urls()


@admin.register(TechnicalEndpoint)
class TechnicalEndpointAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "http_method",
        "path",
        "slug",
        "enabled",
        "created_at",
        "updated_at",
    )

    list_filter = (
        "http_method",
        "enabled",
    )

    search_fields = (
        "name",
        "slug",
        "path",
        "description",
    )

    readonly_fields = (
        "id",
        "slug",
        "created_at",
        "updated_at",
    )

    ordering = (
        "path",
        "http_method",
    )

    fieldsets = (
        (
            "Endpoint",
            {
                "fields": (
                    "id",
                    "name",
                    "slug",
                    "http_method",
                    "path",
                ),
            },
        ),
        (
            "Descrição",
            {
                "fields": (
                    "description",
                ),
            },
        ),
        (
            "Estado",
            {
                "fields": (
                    "enabled",
                ),
            },
        ),
        (
            "Auditoria",
            {
                "fields": (
                    "created_at",
                    "updated_at",
                ),
            },
        ),
    )


@admin.register(ServiceTechnicalEndpoint)
class ServiceTechnicalEndpointAdmin(admin.ModelAdmin):
    list_display = (
        "service",
        "endpoint",
        "enabled",
        "created_at",
        "updated_at",
    )

    list_filter = (
        "enabled",
        "service",
        "endpoint__http_method",
    )

    search_fields = (
        "service__name",
        "service__slug",
        "endpoint__name",
        "endpoint__slug",
        "endpoint__path",
    )

    readonly_fields = (
        "id",
        "created_at",
        "updated_at",
    )

    autocomplete_fields = (
        "service",
        "endpoint",
    )

    ordering = (
        "service__name",
        "endpoint__path",
    )

    fieldsets = (
        (
            "Autorização",
            {
                "fields": (
                    "id",
                    "service",
                    "endpoint",
                    "enabled",
                ),
            },
        ),
        (
            "Auditoria",
            {
                "fields": (
                    "created_at",
                    "updated_at",
                ),
            },
        ),
    )