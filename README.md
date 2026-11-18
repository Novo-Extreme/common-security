# common-security

Biblioteca Maven compartilhada de validação de JWT e permissões dos serviços do **Extreme 2.0**
(ERP telecom da Vonex). Não é serviço: não tem deploy, banco nem Kafka.

> **A documentação mora no [`rag-xtreme`](https://github.com/Novo-Extreme/rag-xtreme/blob/main/README.md)** — veja a [ficha da lib](https://github.com/Novo-Extreme/rag-xtreme/blob/main/technical/services/common-security.md).
> Este README só mostra como começar. Se divergir do RAG, vale o RAG; se o RAG estiver errado,
> corrija lá.

## O que é

Uma Spring Boot auto-configuration (`META-INF/spring/...AutoConfiguration.imports`): basta entrar no
classpath do serviço. Tudo é `@ConditionalOnMissingBean`, então o serviço pode substituir qualquer peça.

| Peça | O que faz |
|---|---|
| `SecurityConfig` | `SecurityFilterChain` stateless, CORS aberto sem credenciais. Públicos: swagger/`/v3/api-docs/**`, `/error`, `/actuator/health`, `/actuator/health/**` e `/actuator/info`. O resto exige token (`anyRequest().authenticated()`) |
| `SecurityFilter` | Lê `Authorization: Bearer`, valida e popula o `SecurityContext` (authorities = permissões do token ou `ROLE_<role>`). Token inválido só loga; a request cai no `authenticated()` |
| `JwtTokenValidator` | HMAC256 com `security.secretKey`, issuer `auth`. Monta o `UserContext` a partir de `userId`, `login`, `name`, `roles`, `permissions` (opcional) e `organizationalContext` |
| `PermissionInterceptor` | Interceptor em `/**` (exceto actuator, swagger e `/error`): põe o `UserContext` no atributo `userContext` da request e aplica `@RequiresPermission` |
| `@RequiresPermission(value, requireAll, message)` | Em método ou classe. Sem `UserContext` → 401; `ADMIN` passa; sem a permissão → 403 |
| `RolePermissionResolver` | Token sem claim `permissions` (JWT enxuto): resolve pelas roles com `GET {services.access-control.url}/api/v1/roles/permissions`, cache com TTL. Mapa não carregado → 403 (fail-closed) |
| `OrganizationalFilterService` | `getAccessibleAccountIds` → `GET /api/v1/access-control/users/{userId}/accessible-accounts` |
| `UserContext` | Identidade + contexto organizacional (carteiras, equipes, canais, segmentos, agentes comerciais, pós-venda); `isAdmin()`, `isCustomerScoped()`, `hasCommercialScope()` etc. |

Propriedades que o serviço consumidor configura (nomes; valores ficam no ConfigMap/Secret de cada ambiente):

| Propriedade | Obrigatória | Padrão |
|---|---|---|
| `security.secretKey` | sim (mesmo segredo do `authentication-service`) | — |
| `services.access-control.url` | na prática sim, se usar `@RequiresPermission` | `http://localhost:8081` |
| `security.role-permissions.ttl-minutes` | não | `10` |
| `security.permission.enabled` | não (`false` desliga a `SecurityAutoConfiguration`) | `true` |
| `security.actuator.prometheus-public` | não | `false` |

### Actuator

Sem token só `/actuator/health`, `/actuator/health/**` (probes do Kubernetes) e `/actuator/info`. Os
demais (`env`, `configprops`, `heapdump`, `loggers`, `metrics`, `prometheus`...) exigem JWT, porque o
ingress encaminha `/<servico>/actuator/**` para o serviço. Se o Prometheus do cluster for raspar o
serviço, ligue `security.actuator.prometheus-public: true` **e** bloqueie
`/<servico>/actuator/prometheus` no ingress (acesso só pela rede interna).

## Versão atual

- `pom.xml` da `main`: **1.1.1**. Última tag: `v1.1.1` (Release "Latest" de 12/11/2026).
- Histórico: tags `v1.0.x` até `v1.0.14`, `v1.1.0` (permissões resolvidas por role com cache, JWT
  enxuto) e `v1.1.1` (`/actuator/**` deixa de ser público; só `health` e `info`).

```bash
git tag --sort=-v:refname | head
gh release list -R Novo-Extreme/common-security
```

## Como consumir

No `pom.xml` do serviço (o `groupId` é `br.com.vonex`):

```xml
<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/Novo-Extreme/common-security</url>
    </repository>
</repositories>

<dependency>
    <groupId>br.com.vonex</groupId>
    <artifactId>common-security</artifactId>
    <version>1.1.1</version>
</dependency>
```

- **Local:** o GitHub Packages exige autenticação até para ler. No `~/.m2/settings.xml`, um
  `<server>` com o mesmo `id` do repositório (`github`), seu usuário do GitHub e um token clássico
  com escopo `read:packages`. Nunca commite o token.
- **Pipeline:** no workflow do serviço (`develop.yaml`, `homolog.yaml`, `main.yaml`), passe
  `github-packages: true` para o `extreme-pipeline`; ele injeta o token no build como BuildKit secret.
- Não precisa declarar filtro nem interceptor: a auto-configuration registra os dois. Para proteger
  um endpoint, anote o controller ou o método com `@RequiresPermission("RECURSO:ACAO")`. Sem a
  anotação a lib só garante "tem token válido".

## Quem usa

Conferido no `pom.xml` dos repos em 18/11/2026:

| Serviço | `main` | `homolog` | `develop` |
|---|---|---|---|
| `account-service` | 1.1.1 | 1.1.1 | 1.1.1 |
| `ci-service` | 1.1.0 | 1.1.1 | 1.1.1 |
| `customer-service` | 1.1.1 | 1.1.1 | 1.1.1 |
| `summary-service` | 1.1.1 | 1.1.1 | 1.1.1 |
| `support-service` | 1.1.0 | 1.1.0 | 1.1.0 |
| `sync-service` | 1.1.0 | 1.1.0 | 1.1.0 |

`virtual-line-service` declara 1.0.0 só na `develop`. Os demais backends não usam a lib (têm
`TokenService` próprio ou não validam token). `support-service` substitui o `SecurityFilterChain`
por um próprio, e `summary-service` não define `services.access-control.url`.

## Testes

```bash
mvn test   # obrigatório antes de commit/push; testes unitários, sem banco nem rede
```

O `.github/workflows/ci.yaml` roda em push e PR para `main` e `develop`: `mvn clean install
-DskipTests`, `mvn test`, `mvn verify` e guarda o JAR como artefato por 7 dias. Não publica nada.

## Como publicar uma versão

O `.github/workflows/publish.yaml` dispara com tag `v*.*.*`: ajusta a versão do `pom.xml` para a da
tag (`mvn versions:set`), roda `mvn clean verify`, faz `mvn deploy` no GitHub Packages e cria a Release
com o JAR e notas geradas.

1. Branch a partir da `main`; altere o código e faça o bump da `<version>` no `pom.xml`.
2. `mvn test` e PR para a `main` (o `ci.yaml` roda no PR).
3. Depois do merge, crie a tag no commit da `main` e envie:
   `git tag vX.Y.Z && git push origin vX.Y.Z` (a tag deve bater com o `pom.xml`; use sempre uma
   versão nova).
4. Confira a Release (`gh release list -R Novo-Extreme/common-security`).
5. Nos serviços consumidores, bump da versão no `pom.xml` em PR próprio, promovido pelo gitflow
   normal do serviço (`develop` → `homolog` → `main`). A lib só vale no ambiente depois do deploy do
   serviço.

## Gitflow

- A `main` é a única branch longa (não existe `develop` nem `homolog` neste repo; o `ci.yaml` ainda
  lista `develop`).
- Branch de trabalho a partir da `main`, merge comum (sem squash), sem branches auxiliares.
- Commit: `tipo(escopo): 🚧 (XTR-XXX) descrição curta`.

Detalhes: [gitflow](https://github.com/Novo-Extreme/rag-xtreme/blob/main/standards/git-workflow/branches-e-commits.md) ·
[pipeline e CI](https://github.com/Novo-Extreme/rag-xtreme/blob/main/technical/operations/pipeline-ci.md).

## Dono e contatos

- Time Extreme 2.0 (Vonex). Não há dono formal por repo.
- Quem mais mexeu nos últimos 6 meses: Thalles Silva.
- Pipeline (`extreme-pipeline`) e runners: João Krauchenco. Manifests (`kubernetes`): time Extreme 2.0.
- Regra de negócio: PO do Extreme 2.0 — dúvidas abertas em
  [perguntas abertas](https://github.com/Novo-Extreme/rag-xtreme/blob/main/business/perguntas-abertas.md).
