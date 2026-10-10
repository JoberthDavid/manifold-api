from apps.integrations.models import Integration, IntegrationOperation
from apps.security.models import (
    Service,
    TechnicalEndpoint,
    ServiceTechnicalEndpoint,
)


SCRAPER_BASE_URL = "http://127.0.0.1:8003"


OPERATIONS = [
    {
        "name": "Buscar composições",
        "slug": "buscar-composicoes",
        "path": "/composicoes/",
        "request_schema": {
            "query": {
                "generic_item__code__in": "generic_item__code__in",
            }
        },
    },
    {
        "name": "Buscar atividades de composição",
        "slug": "buscar-atividades-composicao",
        "path": "/compositions/activities/",
        "request_schema": {
            "query": {
                "composition_code__in": "composition_code__in",
                "limit": "limit",
                "data_base": "data_base",
            }
        },
    },
    {
        "name": "Buscar transportes de composição",
        "slug": "buscar-transportes-composicao",
        "path": "/compositions/transports/",
        "request_schema": {
            "query": {
                "composition_code__in": "composition_code__in",
                "limit": "limit",
                "data_base": "data_base",
            }
        },
    },
    {
        "name": "Buscar valores monetários",
        "slug": "buscar-valores-monetarios",
        "path": "/valores-monetarios/",
        "request_schema": {
            "query": {
                "generic_item": "generic_item",
                "generic_item__in": "generic_item__in",
                "type_system": "type_system",
                "source_file": "source_file",
                "classification": "classification",
                "group": "group",
                "unit": "unit",
            }
        },
    },
]


# ============================================================
# 1. SCRAPER — INTEGRATION
# ============================================================

integration, created = Integration.objects.get_or_create(
    slug="scraper",
    defaults={
        "name": "Scraper",
        "integration_type": "REST_API",
        "authentication_type": "NONE",
        "base_url": SCRAPER_BASE_URL,
        "enabled": True,
        "timeout": 10,
    },
)

if not created:
    integration.name = "Scraper"
    integration.integration_type = "REST_API"
    integration.authentication_type = "NONE"
    integration.base_url = SCRAPER_BASE_URL
    integration.enabled = True
    integration.timeout = 10
    integration.save()


print(
    f"[Integration] "
    f"{'CRIADA' if created else 'ATUALIZADA'}: "
    f"{integration.name} ({integration.slug})"
)


# ============================================================
# 2. INTEGRATION OPERATIONS
# ============================================================

for item in OPERATIONS:
    operation, created = IntegrationOperation.objects.get_or_create(
        integration=integration,
        slug=item["slug"],
        defaults={
            "name": item["name"],
            "http_method": "GET",
            "path": item["path"],
            "request_schema": item["request_schema"],
            "enabled": True,
        },
    )

    if not created:
        operation.name = item["name"]
        operation.http_method = "GET"
        operation.path = item["path"]
        operation.request_schema = item["request_schema"]
        operation.enabled = True
        operation.save()

    print(
        f"[Operation] "
        f"{'CRIADA' if created else 'ATUALIZADA'}: "
        f"{operation.slug} → {operation.path}"
    )


# ============================================================
# 3. COMPOSITION ENGINE — SERVICE
# ============================================================

service = Service.objects.filter(
    slug="composition-engine"
).first()

if service is None:
    service = Service.objects.filter(
        name__iexact="Composition Engine"
    ).first()

if service is None:
    raise RuntimeError(
        "Service 'Composition Engine' não encontrado. "
        "Nenhum Service novo será criado."
    )

if not service.enabled:
    raise RuntimeError(
        "O Service 'Composition Engine' está desabilitado."
    )

print(
    f"[Service] encontrado: "
    f"{service.name} ({service.slug})"
)


# ============================================================
# 4. TECHNICAL ENDPOINTS + AUTORIZAÇÃO
# ============================================================

for item in OPERATIONS:
    technical_path = (
        "/api/integrations/"
        f"scraper/{item['slug']}/"
    )

    endpoint, created = TechnicalEndpoint.objects.get_or_create(
        http_method="GET",
        path=technical_path,
        defaults={
            "name": (
                f"{item['name']} - "
                "Composition Engine"
            ),
            "description": (
                "Endpoint técnico do Manifold para consumo "
                "pelo Composition Engine."
            ),
            "enabled": True,
        },
    )

    if not created:
        endpoint.name = (
            f"{item['name']} - "
            "Composition Engine"
        )
        endpoint.description = (
            "Endpoint técnico do Manifold para consumo "
            "pelo Composition Engine."
        )
        endpoint.enabled = True
        endpoint.save()

    print(
        f"[TechnicalEndpoint] "
        f"{'CRIADO' if created else 'ATUALIZADO'}: "
        f"{endpoint}"
    )

    authorization, created = (
        ServiceTechnicalEndpoint.objects.get_or_create(
            service=service,
            endpoint=endpoint,
            defaults={
                "enabled": True,
            },
        )
    )

    if not created:
        authorization.enabled = True
        authorization.save()

    print(
        f"[Authorization] "
        f"{'CRIADA' if created else 'ATUALIZADA'}: "
        f"{service.name} → {endpoint.path}"
    )


# ============================================================
# 5. CONFERÊNCIA
# ============================================================

print()
print("=" * 70)
print("CONFIGURAÇÃO FINAL")
print("=" * 70)

print()
print("INTEGRATION")
print(f"  name:          {integration.name}")
print(f"  slug:          {integration.slug}")
print(f"  base_url:      {integration.base_url}")
print(f"  authentication:{integration.authentication_type}")
print(f"  enabled:       {integration.enabled}")

print()
print("OPERATIONS")

for operation in IntegrationOperation.objects.filter(
    integration=integration
).order_by("slug"):
    print(
        f"  GET {operation.path}"
        f"  [{operation.slug}]"
        f"  enabled={operation.enabled}"
    )

print()
print("TECHNICAL ENDPOINTS")

for item in OPERATIONS:
    technical_path = (
        "/api/integrations/"
        f"scraper/{item['slug']}/"
    )

    endpoint = TechnicalEndpoint.objects.get(
        http_method="GET",
        path=technical_path,
    )

    authorized = ServiceTechnicalEndpoint.objects.filter(
        service=service,
        endpoint=endpoint,
        enabled=True,
    ).exists()

    print(
        f"  GET {endpoint.path}"
        f"  authorized={authorized}"
    )

print()
print("=" * 70)
print("CONFIGURAÇÃO CONCLUÍDA")
print("=" * 70)
