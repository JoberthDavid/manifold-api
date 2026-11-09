# Guia técnico — Integração de serviços externos ao Manifold

- **Código:** MAN-INF-DEV-001
- **Versão:** 1.0.0
- **Data:** 2026-11-09
- **Status:** baseline técnico; adaptar ao framework do serviço sem alterar o contrato de segurança.

## 1. Objetivo e regra arquitetural

Este guia especifica o que um serviço REST externo deve implementar para ser chamado pelo gateway do Manifold usando autenticação `MANIFOLD_JWT`.

**Não se propõe alteração no código-fonte do `manifold-api` para cada novo serviço.** O serviço novo deve implementar o contrato de autenticação/autorização e suas rotas; em seguida, os registros correspondentes devem ser cadastrados no banco de dados do Manifold.

O cadastro no banco é necessário para que o gateway conheça a integração, as operações e as rotas públicas. Consulte `MAN-INF-OPS-001 — Cadastro de serviços e operações no Manifold`.

## 2. Fluxo de integração

1. O cliente (por exemplo, Angular) chama a rota pública do Manifold usando a sessão/token de usuário aceito pelo Manifold.
2. O Manifold autentica o usuário.
3. O Manifold resolve os registros `TechnicalEndpoint` e `IntegrationOperation`.
4. O gateway lê a configuração de autenticação da operação.
5. O Manifold emite um JWT assinado para o serviço externo, com audiência e escopos cadastrados.
6. O Manifold encaminha a requisição para a base URL da Integration mais o path da operação, incluindo `Authorization: Bearer <JWT>`.
7. O serviço valida o JWT usando as chaves públicas publicadas pelo JWKS do Manifold.
8. O serviço autoriza a ação pelo escopo exigido e executa a operação.
9. A resposta retorna pelo gateway ao cliente.

### Dois contextos diferentes

- **Entrada no Manifold:** autenticação do usuário/cliente perante o Manifold.
- **Saída do Manifold:** JWT de integração que o Manifold envia ao serviço.

O serviço externo valida o segundo token. Não deve confundi-lo com a sessão original do usuário.

## 3. JWT: contrato observado

O padrão examinado usa assinatura EdDSA com chave Ed25519 e publicação de chaves públicas em JWKS.

| Claim/campo | Validação |
|---|---|
| `iss` | Emissor; valor observado: `manifold-api` |
| `sub` | Sujeito; no fluxo de usuário observado começa com `user:` |
| `aud` | Audiência do serviço destinatário |
| `scope` | Lista de escopos da operação |
| `iat` | Instante de emissão |
| `exp` | Expiração |
| `jti` | Identificador do token |
| `kid` | Identificador da chave no cabeçalho JWT |

O TTL padrão observado no Manifold é de 300 segundos. O serviço deve validar a expiração e não presumir validade durante toda a sessão do usuário.

## 4. JWKS

O serviço deve consultar:

```text
/.well-known/jwks.json
```

URL local observada:

```text
http://127.0.0.1:8000/.well-known/jwks.json
```

Em homologação/produção, configurar a URL HTTPS correspondente ao ambiente.

Requisitos:

- fazer requisição HTTP com timeout;
- validar que a resposta é JSON e contém `keys`;
- ler `kid` do cabeçalho JWT sem confiar ainda no token;
- localizar no JWKS a chave correspondente;
- aceitar somente `alg=EdDSA`, `kty=OKP`, `crv=Ed25519` no padrão observado;
- validar criptograficamente a assinatura;
- manter cache de duração limitada (300 segundos no `composition_engine`);
- atualizar o JWKS quando a chave não for encontrada, considerando rotação;
- nunca armazenar ou solicitar a chave privada do Manifold.

## 5. Configuração no serviço consumidor

Configurar por ambiente:

| Variável | Regra |
|---|---|
| `MANIFOLD_JWKS_URL` | Obrigatória; URL completa do JWKS do ambiente |
| `MANIFOLD_JWT_ISSUER` | `manifold-api` no padrão observado |
| `MANIFOLD_JWT_AUDIENCE` | Identificador do serviço, por exemplo `budget-engine` |

Essas são configurações do **serviço consumidor**. Não são configurações a adicionar no Manifold para cada integração.

Não confundir com credenciais/URLs usadas pelo serviço para fazer chamadas de saída ao Manifold. Este documento trata do token recebido pelo serviço quando o Manifold o chama.

## 6. Requisitos de implementação

### 6.1 Extração do Bearer token

- Ler `Authorization`.
- Aceitar o esquema `Bearer`.
- Rejeitar cabeçalho malformado.
- Retornar `401 Unauthorized` para token ausente em rota protegida.
- Nunca registrar o token integral.

### 6.2 Validação criptográfica e de claims

Validar no mínimo:

1. assinatura com a chave pública do JWKS;
2. algoritmo exatamente `EdDSA`;
3. `kid` presente e correspondente a uma chave válida;
4. `iss` igual a `MANIFOLD_JWT_ISSUER`;
5. `aud` igual a `MANIFOLD_JWT_AUDIENCE`;
6. claims obrigatórias `iss`, `sub`, `aud`, `scope`, `iat`, `exp`, `jti`;
7. expiração e verificações temporais;
8. `sub` não vazio e compatível com o fluxo adotado (prefixo `user:` no fluxo observado);
9. `scope` como lista de strings não vazias.

Token ausente, inválido, expirado, com assinatura incorreta, emissor/audiência incorretos ou claims inválidas deve resultar em `401`.

Não aceitar algoritmos alternativos nem desabilitar verificações de assinatura, emissor ou audiência.

### 6.3 Autorização por escopo

Autenticação válida não concede acesso irrestrito. Cada rota deve exigir um escopo explícito.

Exemplos:

| Operação | Escopo |
|---|---|
| Consultar estações pluviométricas | `ner:stations:read` |
| Criar cálculo NER | `ner:calculations:create` |

Se o JWT for válido, mas não contiver o escopo exigido, retornar `403 Forbidden`.

Os escopos devem ser específicos, documentados e coincidir exatamente entre cadastro no Manifold e verificação no serviço.

### 6.4 Aplicar por rota

Proteger apenas as rotas que participam da integração, salvo decisão arquitetural diferente e documentada. Não substituir configurações globais de autenticação/permissão sem avaliar os demais endpoints.

Em Django REST Framework, podem ser usadas classes de autenticação e permissão declaradas nas views protegidas. Em FastAPI, o `composition_engine` usa dependências de autenticação e de escopo. Reproduza o contrato, não necessariamente a estrutura ou as bibliotecas do outro projeto.

## 7. Implementação de referência: composition_engine

A implementação já examinada está em:

```text
app/api/security.py
app/config.py
app/api/routes/compositions.py
tests/api/test_security.py
```

Ela realiza:

- extração Bearer;
- carregamento e cache de JWKS (300 segundos);
- seleção da chave por `kid`;
- validação EdDSA/Ed25519;
- validação de issuer, audience e claims obrigatórias;
- validação de `sub` com prefixo `user:`;
- validação de `scope` como lista;
- autorização por escopo;
- respostas `401` para falhas de autenticação e `403` para escopo insuficiente.

O novo serviço deve manter equivalência semântica de segurança, adaptando a implementação ao framework utilizado.

## 8. Dependências

Versões observadas no `composition_engine`:

```text
PyJWT==2.15.1
cryptography==46.0.7
requests
```

Antes de fixar versões em outro projeto, verificar compatibilidade com Python, política de dependências e CI. Não adicionar dependências de FastAPI/Flask a uma aplicação Django apenas para copiar o exemplo.

## 9. Testes mínimos

### Autenticação

- token ausente;
- esquema incorreto;
- JWT malformado;
- assinatura inválida;
- `kid` desconhecido;
- algoritmo diferente de EdDSA;
- emissor incorreto;
- audiência incorreta;
- token expirado;
- claims obrigatórias ausentes;
- sujeito inválido;
- `scope` ausente ou com tipo inválido;
- falha de consulta ao JWKS.

### Autorização

- token válido com escopo correto: permitido;
- token válido sem escopo: `403`;
- token válido com escopo de outra operação: `403`.

### Integração HTTP

- método/path corretos;
- payload válido e inválido;
- códigos de sucesso e erro;
- timeout;
- contratos de resposta;
- ausência de token em logs.

Usar chaves Ed25519/JWKS controlados nos testes unitários, sem depender de uma instância real do Manifold em cada execução. Manter ao menos um teste ponta a ponta em ambiente controlado.

## 10. Cadastro no banco de dados do Manifold

O serviço não se registra automaticamente por publicar uma rota. O administrador deve cadastrar os registros:

### 10.1 Integration — um registro por serviço

- nome e slug;
- tipo `REST_API`;
- autenticação `MANIFOLD_JWT`;
- base URL alcançável pelo Manifold;
- timeout;
- estado habilitado.

### 10.2 IntegrationOperation — um registro por operação

- Integration relacionada;
- nome e slug;
- método HTTP;
- path relativo do serviço externo;
- estado habilitado;
- `request_schema.authentication.audience`;
- `request_schema.authentication.scopes`.

Exemplo:

```json
{
  "authentication": {
    "audience": "budget-engine",
    "scopes": ["ner:stations:read"]
  }
}
```

### 10.3 TechnicalEndpoint — rota pública no Manifold

- nome e slug;
- método HTTP;
- path público;
- estado habilitado;
- vínculo com a operação/integração conforme o modelo da versão instalada.

O path público do Manifold pode diferir do path externo.

## 11. Convenções recomendadas

- Audience: identificador estável, minúsculo, por exemplo `budget-engine`.
- Escopos: `recurso:ação`, por exemplo `ner:stations:read`.
- Slugs: curtos, estáveis e sem acentos.
- Paths externos: relativos à base URL e iniciados por `/`.
- Paths públicos: seguir a convenção do gateway Manifold.
- Ambientes: separar URLs local, homologação e produção.
- Segredos e `.env` reais nunca devem ser versionados.

## 12. Não fazer

- Não alterar o código do Manifold apenas para incluir um serviço REST que segue o contrato existente.
- Não confundir sessão do usuário com JWT de integração.
- Não aceitar JWT apenas por ter assinatura válida.
- Não ignorar issuer, audience, expiração ou escopo.
- Não armazenar chave privada do Manifold no serviço.
- Não registrar tokens completos.
- Não conceder permissões amplas a todo token autenticado.
- Não alterar autenticação global sem avaliar impacto em rotas não relacionadas.

## 13. Critérios de aceite

- [ ] Endpoints REST estáveis.
- [ ] JWKS consultado e validado.
- [ ] Assinatura EdDSA/Ed25519 validada.
- [ ] Issuer, audience, expiração e claims obrigatórias validados.
- [ ] `sub` validado conforme o fluxo adotado.
- [ ] Escopos verificados por operação.
- [ ] `401` e `403` corretos.
- [ ] Testes positivos e negativos de segurança.
- [ ] Configuração externa por ambiente.
- [ ] Integration, IntegrationOperation e TechnicalEndpoint cadastrados no banco do Manifold.
- [ ] Teste pela rota pública do Manifold concluído.
- [ ] Nenhuma alteração no código-fonte do `manifold-api` necessária.

## 14. Histórico

| Versão | Data | Alteração |
|---|---|---|
| 1.0.0 | 2026-11-09 | Primeira versão baseada no fluxo JWT analisado, na implementação `composition_engine` e nos registros observados do Budget Engine. |