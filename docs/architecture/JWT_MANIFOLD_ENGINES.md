# Protocolo JWT Manifold ↔ Engines

**Versão:** 1.0
**Status:** arquitetura proposta


## 1. Objetivo

Definir o padrão de autenticação e autorização entre o `manifold-api` e serviços internos do ecossistema Manifold.

O protocolo deve ser:

- independente de provedor de hospedagem;
- transparente para o usuário;
- aplicável a qualquer Engine/API;
- baseado em tokens JWT assinados pelo Manifold;
- sem exposição de credenciais internas ao frontend;
- capaz de limitar um token a um serviço e operação específicos.


## 2. Arquitetura

O `manifold-api` é a **autoridade de identidade e autorização**.

```text
                    USUÁRIO
                       │
                       ▼
                ┌─────────────┐
                │   Angular   │
                └──────┬──────┘
                       │
                       ▼
                ┌─────────────┐
                │  MANIFOLD   │
                │     API     │
                └──────┬──────┘
                       │
                 JWT assinado
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
   Composition     Budget         GIS
     Engine        Engine        Engine

O frontend nunca chama diretamente os Engines.


## 3. Responsabilidades

Manifold API
Responsável por:
- autenticar o usuário;
- controlar sessão;
- validar organização/projeto;
- verificar permissões;
- emitir JWT;
- assinar JWT;
- controlar chaves de assinatura;
- publicar as chaves públicas;
- definir scope;
- controlar validade e revogação quando necessário.
Engine/API
Responsável por:
- validar assinatura do JWT;
- validar issuer;
- validar audience;
- validar expiração;
- validar scope;
- rejeitar tokens inválidos;
- executar somente a operação autorizada.
O Engine não autentica o usuário diretamente.


##  4. JWT
O Manifold emitirá JWT assinado para chamadas internas.
Formato conceitual:
{
  "iss": "manifold-api",
  "sub": "user:<id>",
  "aud": "composition-engine",
  "scope": [
    "composition:calculate"
  ],
  "iat": 1790000000,
  "exp": 1790000300,
  "jti": "<uuid>"
}

Claims obrigatórios
Claim	Finalidade
iss	identifica o emissor
sub	identifica o sujeito/contexto autorizado
aud	identifica o Engine destinatário
scope	operações permitidas
iat	momento da emissão
exp	expiração
jti	identificador único do token


O aud é fundamental:
aud = composition-engine

não deve ser aceito pelo:
budget-engine


## 5. Assinatura
O Manifold utiliza criptografia assimétrica.
Manifold
   │
   └── PRIVATE KEY
          │
          ▼
       assina JWT

Os Engines recebem somente a chave pública:
Composition Engine
       │
       └── PUBLIC KEY
              │
              ▼
         verifica JWT

A chave privada nunca é enviada aos Engines.
Algoritmo
Adotaremos inicialmente:
EdDSA / Ed25519
por ser adequado para assinatura/verificação rápida e possuir chaves pequenas.


## 6. Distribuição das chaves públicas
O Manifold disponibilizará um endpoint JWKS:
/.well-known/jwks.json

Cada Engine poderá obter e manter em cache as chaves públicas.
Durante uma rotação, o Manifold poderá publicar simultaneamente a chave pública atual e a anterior, permitindo trocar chaves sem interromper as APIs.


## 7. Chamada entre serviços
O Manifold enviará:
Authorization: Bearer <JWT>

Exemplo:
POST /compositions/0919013/calculate
Authorization: Bearer eyJ...
Content-Type: application/json

O Engine deverá validar o token antes de executar a operação.


## 8. Scopes
Os scopes seguem o padrão:
<domínio>:<operação>

Exemplos:
composition:read
composition:calculate
composition:explosion

budget:read
budget:calculate

gis:read
gis:route

sicro:read
sicro:search

Um Engine deve aceitar somente scopes pertencentes ao seu domínio.
Exemplo válido:
aud = composition-engine
scope = composition:calculate

Exemplo que deve ser rejeitado:
aud = composition-engine
scope = budget:calculate


## 9. Validade
Tokens de comunicação interna terão vida curta.
Referência inicial:
TTL = 5 minutos

O token deve ser emitido sob demanda, para a operação.
Não devemos criar tokens permanentes.


## 10. Contexto da operação
O JWT pode carregar somente o contexto necessário.
Por exemplo:
{
  "iss": "manifold-api",
  "sub": "user:<id>",
  "aud": "budget-engine",
  "scope": [
    "budget:calculate"
  ],
  "organization": "<organization-id>",
  "project": "<project-id>",
  "iat": 1790000000,
  "exp": 1790000300,
  "jti": "<uuid>"
}

Não devemos transformar o JWT em um depósito de dados do usuário. Somente informações necessárias para autorização devem ser colocadas no token.


## 11. Fluxo padrão
1. Usuário solicita operação
             ↓
2. Angular → Manifold
             ↓
3. Manifold autentica/autorização
             ↓
4. Manifold cria JWT
             ↓
5. Manifold → Engine
             ↓
6. Engine valida JWT
             ↓
7. Engine executa operação
             ↓
8. Engine → Manifold
             ↓
9. Manifold → Angular
             ↓
10. Usuário recebe resultado

O usuário não participa da comunicação entre Manifold e Engine.


## 12. E-mail / 2FA
O e-mail pertence à autenticação do usuário, não à comunicação entre serviços.
Usuário
   │
   ├── senha
   │
   └── código e-mail
          ↓
      Manifold
          ↓
    usuário autenticado

Depois disso:
Manifold
   │
   └── JWT
          ↓
       Engine

O código enviado por e-mail nunca é encaminhado ao Engine.


## 13. Revogação
Como os tokens têm vida curta, não haverá necessidade de consultar o Manifold para cada requisição.
Para situações excepcionais — comprometimento de uma sessão, usuário, organização ou serviço — poderemos futuramente implementar:
- jti blacklist;
- versionamento de credenciais;
- revogação de sessão;
- invalidação por organização;
- rotação de chaves.
A implementação inicial pode trabalhar somente com:
assinatura + audience + scope + expiração


## 14. Credenciais externas
IntegrationCredential permanece separado do JWT.
                    MANIFOLD
                       │
          ┌────────────┴────────────┐
          │                         │
     JWT interno              Credenciais
          │                     externas
          ▼                         ▼
      Engines                 SICRO/SINAPI/
                              outras APIs

IntegrationCredential continua utilizando:
encrypted_value
fingerprint

e nunca será exposto ao Angular.


## 15. Regra fundamental
Nenhum Engine deve confiar diretamente no frontend ou em uma credencial armazenada no frontend.

A confiança é:
Angular
   ↓
Manifold
   ↓
JWT assinado
   ↓
Engine

O Manifold é a raiz de confiança do ecossistema.


## 16. Aplicabilidade
O mesmo protocolo será utilizado por:
manifold-api
    │
    ├── composition-engine
    ├── budget-engine
    ├── GIS engine
    ├── SICRO API
    ├── SINAPI API
    └── futuros serviços

Cada serviço terá apenas três elementos específicos:
service_id
audience
scopes

O mecanismo de autenticação permanece o mesmo.


## Decisão arquitetural
O Manifold API é a autoridade central de identidade e autorização. Serviços internos confiam no Manifold por meio de JWTs assimetricamente assinados, destinados exclusivamente ao serviço receptor e com escopo e validade limitados. O frontend nunca se comunica diretamente com serviços internos.