# Procedimento operacional — Cadastro de serviços e operações no Manifold

- **Código:** MAN-INF-OPS-001
- **Versão:** 1.0.0
- **Data:** 2026-11-09
- **Status:** baseline técnico; conferir os rótulos e a sequência da interface Admin na versão implantada.

## 1. Objetivo

Padronizar o cadastro, no Manifold, de um serviço REST externo, das operações que serão encaminhadas pelo gateway e das rotas públicas que os consumidores chamarão.

## 2. Princípio

A inclusão de um novo serviço que siga o contrato de integração existente é feita por configuração e cadastro no banco de dados do Manifold. Não se deve presumir que seja necessária alteração no código-fonte do `manifold-api`.

Há três conceitos distintos:

- **Integration:** serviço externo, parâmetros gerais de conexão e autenticação.
- **IntegrationOperation:** operação externa específica (método, path, esquema e autenticação).
- **TechnicalEndpoint:** rota técnica pública exposta pelo Manifold para o consumidor.

Os registros devem estar coerentemente relacionados. Criar um deles não significa que os outros sejam criados automaticamente.

## 3. Referência confirmada: Budget Engine

### 3.1 Integration

| Campo | Valor observado |
|---|---|
| Nome | `Budget Engine` |
| Slug | `budget-engine` |
| Tipo | `REST_API` |
| Autenticação | `MANIFOLD_JWT` |
| Base URL local | `http://127.0.0.1:8002` |
| Habilitada | `True` |
| Timeout | `10` |

UUID observado: `b539c5ea-e50d-4e67-94f4-58a32462b8b8`.

A URL `127.0.0.1` é apenas referência do ambiente local. Em outros ambientes, a base URL precisa ser alcançável a partir do processo/container do Manifold.

### 3.2 IntegrationOperation existente

| Campo | Valor observado |
|---|---|
| Nome | `Listar estações pluviométricas` |
| Slug | `listar-estacoes-pluviometricas` |
| Método | `GET` |
| Path externo | `/ner/stations` |
| Habilitada | `True` |

UUID observado: `a11aaff7-06f2-4846-948a-2d04024b5670`.

`request_schema` de autenticação:

```json
{
  "authentication": {
    "audience": "budget-engine",
    "scopes": ["ner:stations:read"]
  }
}
```

O gateway usa `audience` e `scopes` para emitir o JWT de integração destinado ao serviço externo.

### 3.3 TechnicalEndpoint existente

| Campo | Valor observado |
|---|---|
| Nome | `Lista estações pluviométricas - Budget Engine` |
| Slug | `lista-estacoes-pluviometricas` |
| Método | `GET` |
| Path público | `/api/integrations/budget-engine/listar-estacoes-pluviometricas/` |
| Habilitado | `True` |

UUID observado: `86e292cd-2957-4ebe-b046-1663bdfd8b62`.

O consumidor chama a rota pública do Manifold. O gateway encaminha para `/ner/stations` no Budget Engine.

## 4. Procedimento de cadastro no Admin

**Limite documental:** os registros e seus valores foram observados no ambiente. Os nomes exatos dos menus, botões e rótulos visuais do Admin ainda precisam ser conferidos na interface implantada. Este procedimento não inventa nomes de telas.

### Etapa 1 — Preparar os dados

Obter antes do cadastro:

- nome e slug únicos do serviço;
- tipo de integração;
- base URL alcançável a partir do Manifold;
- mecanismo de autenticação;
- timeout;
- lista de operações, métodos e paths externos;
- audiência e escopos exigidos por operação;
- rotas públicas que serão disponibilizadas pelo Manifold.

Testar a conectividade a partir do ambiente do Manifold. Uma URL acessível no navegador do desenvolvedor pode não ser acessível pelo servidor ou container.

### Etapa 2 — Criar a Integration

Na área de administração de integrações do Manifold:

1. criar o registro do serviço;
2. informar nome e slug;
3. selecionar o tipo REST (`REST_API`, no padrão observado);
4. selecionar `MANIFOLD_JWT`, quando o serviço validar JWT emitido pelo Manifold;
5. informar a base URL e o timeout;
6. definir o estado habilitado conforme a prontidão do serviço;
7. salvar e reabrir o registro para confirmar a persistência.

A base URL deve conter somente a origem/base do serviço, não o path de uma operação.

### Etapa 3 — Criar uma IntegrationOperation por operação

Para cada operação que será encaminhada:

1. associar à Integration correta;
2. informar nome e slug;
3. informar método HTTP;
4. informar path relativo à base URL externa;
5. definir o estado habilitado;
6. preencher `request_schema.authentication` com audiência e escopos.

Exemplo:

```json
{
  "authentication": {
    "audience": "nome-do-servico",
    "scopes": ["recurso:acao"]
  }
}
```

Regras essenciais:

- `audience` deve coincidir exatamente com a audiência validada pelo serviço;
- os escopos devem coincidir exatamente com os verificados na rota;
- o path é externo, relativo à base URL, sem host;
- não habilitar a operação antes de testar a rota no serviço.

### Etapa 4 — Criar o TechnicalEndpoint

Para cada rota pública que o consumidor chamará:

1. informar nome e slug;
2. informar método HTTP;
3. informar o path público do Manifold;
4. habilitar após validação;
5. estabelecer o vínculo com a operação/integração conforme o modelo da versão instalada.

O path público do Manifold não precisa ser igual ao path externo. Exemplo confirmado:

- público: `/api/integrations/budget-engine/listar-estacoes-pluviometricas/`
- externo: `/ner/stations`

Verificar colisões de método/path e se o endpoint aponta para a operação correta.

### Etapa 5 — Revisão de consistência

Conferir:

- Integration habilitada, URL e timeout corretos;
- IntegrationOperation vinculada à Integration correta;
- método e path externos corretos;
- audiência e escopos exatos;
- TechnicalEndpoint habilitado e relacionado à operação;
- método e path públicos corretos;
- ausência de slugs/rotas duplicados.

### Etapa 6 — Teste ponta a ponta

1. Testar o endpoint externo diretamente com token válido.
2. Chamar a rota pública do Manifold com sessão de usuário válida.
3. Confirmar a emissão do JWT de integração e o encaminhamento.
4. Confirmar validação de assinatura, emissor, audiência, validade e escopo no serviço.
5. Testar ausência de token, token inválido/expirado, audiência incorreta e escopo insuficiente.
6. Verificar códigos HTTP e logs, sem registrar tokens completos.

## 5. Exemplo: cadastrar criação de cálculo NER

### IntegrationOperation proposta

| Campo | Valor |
|---|---|
| Integration | `Budget Engine` |
| Nome | `Criar cálculo NER` |
| Slug | `criar-calculo-ner` |
| Método | `POST` |
| Path externo | `/ner/calculations` |
| Audience | `budget-engine` |
| Scope | `ner:calculations:create` |

```json
{
  "authentication": {
    "audience": "budget-engine",
    "scopes": ["ner:calculations:create"]
  }
}
```

### TechnicalEndpoint proposto

| Campo | Valor |
|---|---|
| Nome | `Criar cálculo NER - Budget Engine` |
| Slug | `criar-calculo-ner` |
| Método | `POST` |
| Path público | `/api/integrations/budget-engine/criar-calculo-ner/` |

Esses são valores propostos para o novo cadastro, não confirmação de que os registros já existam.

## 6. Segurança e operação

- Não registrar JWTs completos em logs.
- Não armazenar chave privada do Manifold no serviço externo.
- Obter chaves públicas pelo JWKS do Manifold.
- Usar HTTPS fora do ambiente local isolado.
- Restringir audiência e escopos por operação.
- Usar timeout compatível com o processamento.
- Respeitar `kid` e cache JWKS com expiração limitada.
- Não reutilizar slugs com significado diferente.
- Aplicar autenticação apenas às rotas que dela necessitam; não alterar permissões globais sem avaliar o impacto.

## 7. Checklist de liberação

- [ ] Serviço acessível a partir do Manifold.
- [ ] Integration cadastrada e revisada.
- [ ] IntegrationOperation cadastrada por operação.
- [ ] Audience e escopos conferidos.
- [ ] TechnicalEndpoint cadastrado e relacionado.
- [ ] Rota pública testada com sessão válida.
- [ ] Token inválido/expirado rejeitado.
- [ ] Audiência incorreta rejeitada.
- [ ] Escopo insuficiente rejeitado.
- [ ] Logs sem vazamento de credenciais.
- [ ] Documentação atualizada.

## 8. Histórico

| Versão | Data | Alteração |
|---|---|---|
| 1.0.0 | 2026-11-09 | Primeira versão baseada nos registros observados da integração Budget Engine e no fluxo JWT analisado. |