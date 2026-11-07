package br.com.vonex.common.security.config;

import br.com.vonex.common.security.config.filter.SecurityFilter;
import br.com.vonex.common.security.service.JwtTokenValidator;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Infra compartilhada dos testes de seguranca do actuator: um controller falso nos paths do actuator
 * (o Spring Security casa por path, entao nao precisa do actuator real) e o SecurityFilter da lib.
 */
final class ActuatorSecurityTestSupport {

    static final String SECRET = "test-secret-key-for-actuator-security";

    private ActuatorSecurityTestSupport() {
    }

    static String bearerToken() {
        return "Bearer " + JWT.create()
                .withIssuer("auth")
                .withSubject("user")
                .withClaim("userId", 1L)
                .withClaim("login", "user")
                .withClaim("name", "User")
                .sign(Algorithm.HMAC256(SECRET));
    }

    @RestController
    static class FakeActuatorController {
        @GetMapping({
                "/actuator/health",
                "/actuator/health/liveness",
                "/actuator/health/readiness",
                "/actuator/info",
                "/actuator/env",
                "/actuator/configprops",
                "/actuator/heapdump",
                "/actuator/loggers",
                "/actuator/metrics",
                "/actuator/prometheus"
        })
        String ok() {
            return "ok";
        }
    }

    @Configuration
    static class Beans {
        @Bean
        JwtTokenValidator jwtTokenValidator() {
            return new JwtTokenValidator(SECRET);
        }

        @Bean
        SecurityFilter securityFilter(JwtTokenValidator jwtTokenValidator) {
            return new SecurityFilter(jwtTokenValidator);
        }
    }
}
