// SecurityConfig.java
package br.com.vonex.common.security.config;

import br.com.vonex.common.security.config.filter.SecurityFilter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@AutoConfiguration
@EnableWebSecurity
@RequiredArgsConstructor
@ConditionalOnClass(name = "org.springframework.security.web.SecurityFilterChain")
public class SecurityConfig {

    private final SecurityFilter securityFilter;

    private static final String[] PUBLIC_ENDPOINTS = {
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/error"
    };

    /**
     * Unicos endpoints do actuator liberados sem token: probes do Kubernetes (health/liveness/readiness)
     * e info. Os demais (env, configprops, beans, heapdump, loggers, metrics, prometheus...) exigem
     * autenticacao, porque o ingress expoe {@code /<servico>/actuator/**} para a internet.
     */
    static final String[] PUBLIC_ACTUATOR_ENDPOINTS = {
            "/actuator/health",
            "/actuator/health/**",
            "/actuator/info"
    };

    static final String PROMETHEUS_ENDPOINT = "/actuator/prometheus";

    /**
     * Libera {@code /actuator/prometheus} sem token para o Prometheus do cluster raspar.
     * Ligar so junto com o bloqueio de {@code /<servico>/actuator/prometheus} no ingress
     * (o endpoint deve ficar acessivel apenas pela rede interna).
     */
    @Value("${security.actuator.prometheus-public:false}")
    private boolean prometheusPublic;

    @Bean
    @ConditionalOnMissingBean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((req, rsp, authException) -> {
                            rsp.setContentType("application/json");
                            rsp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            rsp.getWriter().write("{\"error\": \"" + authException.getMessage() + "\"}");
                        })
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .requestMatchers(publicActuatorEndpoints()).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    String[] publicActuatorEndpoints() {
        if (!prometheusPublic) {
            return PUBLIC_ACTUATOR_ENDPOINTS;
        }
        String[] endpoints = Arrays.copyOf(PUBLIC_ACTUATOR_ENDPOINTS, PUBLIC_ACTUATOR_ENDPOINTS.length + 1);
        endpoints[PUBLIC_ACTUATOR_ENDPOINTS.length] = PROMETHEUS_ENDPOINT;
        return endpoints;
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    @ConditionalOnMissingBean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowCredentials(false);

        configuration.setAllowedHeaders(List.of("*"));

        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"
        ));

        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}