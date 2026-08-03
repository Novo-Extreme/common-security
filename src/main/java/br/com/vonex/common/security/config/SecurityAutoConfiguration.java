// SecurityAutoConfiguration.java
package br.com.vonex.common.security.config;

import br.com.vonex.common.security.interceptor.PermissionInterceptor;
import br.com.vonex.common.security.config.filter.SecurityFilter;
import br.com.vonex.common.security.service.JwtTokenValidator;
import br.com.vonex.common.security.service.OrganizationalFilterService;
import br.com.vonex.common.security.service.PermissionValidationService;
import br.com.vonex.common.security.service.RolePermissionResolver;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.Duration;

@Slf4j
@AutoConfiguration
@ConditionalOnClass(name = "org.springframework.web.servlet.DispatcherServlet")
@ConditionalOnProperty(
        prefix = "security.permission",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class SecurityAutoConfiguration {

    public SecurityAutoConfiguration() {
        log.info("========================================");
        log.info("🔐 Security Auto-Configuration LOADED");
        log.info("========================================");
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenValidator jwtTokenValidator(@Value("${security.secretKey}") String secretKey) {
        log.info("✅ Creating JwtTokenValidator bean");
        return new JwtTokenValidator(secretKey);
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionValidationService permissionValidationService() {
        log.info("✅ Creating PermissionValidationService bean");
        return new PermissionValidationService();
    }

    @Bean
    @ConditionalOnMissingBean
    public RolePermissionResolver rolePermissionResolver(
            WebClient accessControlWebClient,
            @Value("${security.role-permissions.ttl-minutes:10}") long ttlMinutes) {
        log.info("✅ Creating RolePermissionResolver bean (TTL: {} min)", ttlMinutes);
        return new RolePermissionResolver(accessControlWebClient, Duration.ofMinutes(ttlMinutes));
    }

    @Bean
    @ConditionalOnMissingBean
    public PermissionInterceptor permissionInterceptor(
            JwtTokenValidator jwtTokenValidator,
            PermissionValidationService permissionValidationService,
            RolePermissionResolver rolePermissionResolver) {
        log.info("✅ Creating PermissionInterceptor bean");
        return new PermissionInterceptor(jwtTokenValidator, permissionValidationService, rolePermissionResolver);
    }

    @Bean
    @ConditionalOnMissingBean(name = "accessControlWebClient")
    public WebClient accessControlWebClient(
            @Value("${services.access-control.url:http://localhost:8081}") String accessControlUrl) {
        log.info("✅ Creating accessControlWebClient bean with URL: {}", accessControlUrl);
        return WebClient.builder()
                .baseUrl(accessControlUrl)
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public OrganizationalFilterService organizationalFilterService(WebClient accessControlWebClient) {
        log.info("✅ Creating OrganizationalFilterService bean");
        return new OrganizationalFilterService(accessControlWebClient);
    }

    @Bean
    public WebMvcConfigurer permissionInterceptorConfigurer(PermissionInterceptor permissionInterceptor) {
        log.info("🛡️ Configuring PermissionInterceptor");
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                log.info("🛡️ Registering interceptor for /**");
                registry.addInterceptor(permissionInterceptor)
                        .addPathPatterns("/**")
                        .excludePathPatterns(
                                "/actuator/**",
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/error"
                        );
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilter securityFilter(JwtTokenValidator jwtTokenValidator) {
        log.info("✅ Creating SecurityFilter bean");
        return new SecurityFilter(jwtTokenValidator);
    }
}