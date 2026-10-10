class EngineClientError(Exception):
    """
    Erro base para falhas relacionadas à comunicação com engines.
    """

    pass


class EngineConfigurationError(EngineClientError):
    """
    Erro de configuração de um client de engine.
    """

    pass


class EngineAuthenticationError(EngineClientError):
    """
    Erro relacionado à autenticação utilizada na comunicação com a engine.
    """

    pass


class EngineRequestError(EngineClientError):
    """
    Erro ocorrido durante uma requisição à engine.
    """

    pass


class EngineResponseError(EngineClientError):
    """
    Erro relacionado a uma resposta inválida ou inesperada da engine.
    """

    pass
