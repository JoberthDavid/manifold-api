class IntegrationError(Exception):
    """Base exception for integration domain errors."""


class IntegrationNotConfiguredError(IntegrationError):
    """Raised when an integration is missing required configuration."""


class IntegrationCredentialError(IntegrationError):
    """Raised when an integration credential cannot be used."""