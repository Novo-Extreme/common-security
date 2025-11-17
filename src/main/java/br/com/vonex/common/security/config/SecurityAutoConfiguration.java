package br.com.vonex.common.security.config;

import br.com.vonex.common.security.interceptor.PermissionInterceptor;
import br.com.vonex.common.security.service.JwtTokenValidator;
import br.com.vonex.common.security.service.PermissionValidationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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
    public PermissionInterceptor permissionInterceptor(
            JwtTokenValidator jwtTokenValidator,
            PermissionValidationService permissionValidationService) {
        log.info("✅ Creating PermissionInterceptor bean");
        return new PermissionInterceptor(jwtTokenValidator, permissionValidationService);
    }

    @Bean
    public WebMvcConfigurer permissionInterceptorConfigurer(PermissionInterceptor permissionInterceptor) {
        log.info("🛡️ Configuring PermissionInterceptor");
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                log.info("🛡️ Registering interceptor for /api/**");
                registry.addInterceptor(permissionInterceptor)
                        .addPathPatterns("/api/**")
                        .excludePathPatterns(
                                "/actuator/**",
                                "/swagger-ui/**",
                                "/v3/api-docs/**"
                        );
            }
        };
    }
}