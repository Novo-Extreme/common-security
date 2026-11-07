# Common Security

Biblioteca de segurança JWT compartilhada para microserviços Vonex.

## 🚀 Instalação

### 1. Adicionar repositório GitHub Packages

Adicione ao seu `pom.xml`:
```xml
<repositories>
    <repository>
        <id>github</id>
        <name>GitHub Packages</name>
        <url>https://maven.pkg.github.com/novo-extreme/common-security</url>
    </repository>
</repositories>
```

### 2. Adicionar dependência
```xml
<dependency>
    <groupId>com.vonex</groupId>
    <artifactId>common-security</artifactId>
    <version>1.0.0</version>
</dependency>
```

### 3. Configurar credenciais

Crie ou edite `~/.m2/settings.xml`:
```xml
<settings>
  <servers>
    <server>
      <id>github</id>
      <username>SEU_GITHUB_USERNAME</username>
      <password>SEU_GITHUB_PERSONAL_ACCESS_TOKEN</password>
    </server>
  </servers>
</settings>
```

**Obter GitHub Token:**
1. GitHub → Settings → Developer settings
2. Personal access tokens → Tokens (classic)
3. Generate new token
4. Selecionar scope: `read:packages`

## 📖 Uso

### Configurar JWT Filter
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

### Configurar Interceptor de Permissões
```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Autowired
    private PermissionInterceptor permissionInterceptor;
    
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(permissionInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/public/**");
    }
}
```

## 🔒 Actuator

O `SecurityFilterChain` da lib libera sem token apenas `/actuator/health`, `/actuator/health/**`
(probes do Kubernetes) e `/actuator/info`. Os demais endpoints do actuator (`env`, `configprops`,
`heapdump`, `loggers`, `metrics`, `prometheus`...) exigem JWT válido, porque o ingress encaminha
`/<servico>/actuator/**` para o serviço.

Se o serviço for raspado pelo Prometheus do cluster, ligar `security.actuator.prometheus-public: true`
**e** bloquear `/<servico>/actuator/prometheus` no ingress: o endpoint deve ficar acessível só pela
rede interna.

## 📦 Versões

- **1.0.0** - Versão inicial com JWT Filter e Permission Interceptor
- **1.1.1** - `/actuator/**` deixa de ser público: só `health` e `info` (e `prometheus` via `security.actuator.prometheus-public`)