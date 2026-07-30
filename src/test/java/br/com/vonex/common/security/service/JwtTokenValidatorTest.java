package br.com.vonex.common.security.service;

import br.com.vonex.common.security.dto.UserContext;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtTokenValidatorTest {

    private static final String SECRET = "test-secret-key-for-jwt-validation";
    private final JwtTokenValidator validator = new JwtTokenValidator(SECRET);

    private String token(Map<String, Object> orgContext) {
        var builder = JWT.create()
                .withIssuer("auth")
                .withClaim("userId", 1L)
                .withClaim("login", "user")
                .withClaim("name", "User");
        if (orgContext != null) {
            builder.withClaim("organizationalContext", orgContext);
        }
        return builder.sign(Algorithm.HMAC256(SECRET));
    }

    @Test
    void noOrgContext_customerScopedFalse() {
        UserContext ctx = validator.validateAndExtractContext(token(null));
        assertFalse(ctx.isCustomerScoped());
    }

    @Test
    void orgContextWithoutKey_legacyDefaultsTrue() {
        Map<String, Object> org = new HashMap<>();
        org.put("teamIds", List.of(11));
        UserContext ctx = validator.validateAndExtractContext(token(org));
        assertTrue(ctx.isCustomerScoped());
    }

    @Test
    void orgContextCustomerScopedFalse_isRead() {
        Map<String, Object> org = new HashMap<>();
        org.put("teamIds", List.of(11));
        org.put("customerScoped", false);
        UserContext ctx = validator.validateAndExtractContext(token(org));
        assertFalse(ctx.isCustomerScoped());
    }

    @Test
    void orgContextCustomerScopedTrue_isRead() {
        Map<String, Object> org = new HashMap<>();
        org.put("customerScoped", true);
        UserContext ctx = validator.validateAndExtractContext(token(org));
        assertTrue(ctx.isCustomerScoped());
    }
}
