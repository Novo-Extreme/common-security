package br.com.vonex.common.security.interceptor;

import br.com.vonex.common.security.annotation.RequiresPermission;
import br.com.vonex.common.security.dto.UserContext;
import br.com.vonex.common.security.service.JwtTokenValidator;
import br.com.vonex.common.security.service.PermissionValidationService;
import br.com.vonex.common.security.service.RolePermissionResolver;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Cobre o fallback do rollout gradual: com o claim no token nada muda; sem o claim, as permissões
 * são resolvidas pelas roles; sem resolver disponível, nega (fail-closed).
 */
class PermissionInterceptorTest {

    @SuppressWarnings("unused")
    static class Protegido {
        @RequiresPermission("CI_DEMAND:LIST")
        public void listar() {
        }
    }

    private JwtTokenValidator jwtValidator;
    private RolePermissionResolver resolver;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private HandlerMethod handler;

    @BeforeEach
    void setUp() throws Exception {
        jwtValidator = mock(JwtTokenValidator.class);
        resolver = mock(RolePermissionResolver.class);
        request = new MockHttpServletRequest("GET", "/api/v1/demands");
        response = new MockHttpServletResponse();
        handler = new HandlerMethod(new Protegido(), Protegido.class.getMethod("listar"));
    }

    private PermissionInterceptor interceptor(RolePermissionResolver rolePermissionResolver) {
        return new PermissionInterceptor(jwtValidator, new PermissionValidationService(), rolePermissionResolver);
    }

    private void authenticate(UserContext context) {
        request.addHeader("Authorization", "Bearer token");
        when(jwtValidator.extractTokenFromHeader(any())).thenReturn("token");
        when(jwtValidator.validateAndExtractContext("token")).thenReturn(context);
    }

    private UserContext user(List<String> roles, List<String> permissions) {
        return UserContext.builder()
                .userId(7L).login("fulano")
                .roles(roles).permissions(permissions)
                .portfolios(List.of())
                .build();
    }

    @Test
    void tokenComClaim_naoConsultaOResolver() {
        authenticate(user(List.of("VIEWER"), List.of("CI_DEMAND:LIST")));

        boolean allowed = interceptor(resolver).preHandle(request, response, handler);

        assertThat(allowed).isTrue();
        verify(resolver, never()).resolvePermissions(any());
    }

    @Test
    void tokenSemClaim_resolvePelasRoles() {
        UserContext context = user(List.of("VIEWER"), null);
        authenticate(context);
        when(resolver.resolvePermissions(List.of("VIEWER"))).thenReturn(Set.of("CI_DEMAND:LIST"));

        boolean allowed = interceptor(resolver).preHandle(request, response, handler);

        assertThat(allowed).isTrue();
        assertThat(context.getPermissions()).containsExactly("CI_DEMAND:LIST");
    }

    @Test
    void tokenSemClaim_resolvidoSemAPermissaoExigida_nega() {
        authenticate(user(List.of("VIEWER"), null));
        when(resolver.resolvePermissions(List.of("VIEWER"))).thenReturn(Set.of("OUTRO:LIST"));

        boolean allowed = interceptor(resolver).preHandle(request, response, handler);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void tokenSemClaim_cacheIndisponivel_negaFailClosed() {
        authenticate(user(List.of("VIEWER"), null));
        when(resolver.resolvePermissions(List.of("VIEWER"))).thenReturn(Set.of());

        boolean allowed = interceptor(resolver).preHandle(request, response, handler);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void semResolver_mantemComportamentoAntigo() {
        authenticate(user(List.of("VIEWER"), null));

        boolean allowed = interceptor(null).preHandle(request, response, handler);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void admin_naoConsultaOResolver() {
        authenticate(user(List.of("ADMIN"), null));

        boolean allowed = interceptor(resolver).preHandle(request, response, handler);

        assertThat(allowed).isTrue();
        verify(resolver, never()).resolvePermissions(any());
    }

    @Test
    void semToken_naoAutorizado() {
        boolean allowed = interceptor(resolver).preHandle(request, response, handler);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
