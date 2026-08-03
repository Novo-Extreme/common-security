package br.com.vonex.common.security.service;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class RolePermissionResolverTest {

    private static final String TWO_ROLES = """
            {"ADMIN":["CI_REGISTRATION:CREATE","CI_DEMAND:LIST"],"VIEWER":["CI_DEMAND:LIST"]}
            """;

    private final AtomicInteger requests = new AtomicInteger();
    private final AtomicReference<String> body = new AtomicReference<>(TWO_ROLES);
    private final AtomicReference<Boolean> failing = new AtomicReference<>(false);

    private WebClient webClient() {
        ExchangeFunction exchange = request -> {
            requests.incrementAndGet();
            if (Boolean.TRUE.equals(failing.get())) {
                return Mono.error(new IllegalStateException("access-control indisponível"));
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body(body.get())
                    .build());
        };
        return WebClient.builder().baseUrl("http://access-control").exchangeFunction(exchange).build();
    }

    private RolePermissionResolver resolver(Duration ttl) {
        return new RolePermissionResolver(webClient(), ttl);
    }

    @Test
    void resolvePermissions_unionOfRoles() {
        Set<String> result = resolver(Duration.ofMinutes(10))
                .resolvePermissions(List.of("ADMIN", "VIEWER"));

        assertThat(result).containsExactlyInAnyOrder("CI_REGISTRATION:CREATE", "CI_DEMAND:LIST");
    }

    @Test
    void resolvePermissions_ignoresUnknownRole() {
        Set<String> result = resolver(Duration.ofMinutes(10))
                .resolvePermissions(List.of("VIEWER", "NUMERACAO_ADMIN"));

        assertThat(result).containsExactly("CI_DEMAND:LIST");
    }

    @Test
    void resolvePermissions_emptyForNullOrEmptyRoles() {
        RolePermissionResolver resolver = resolver(Duration.ofMinutes(10));

        assertThat(resolver.resolvePermissions(null)).isEmpty();
        assertThat(resolver.resolvePermissions(List.of())).isEmpty();
        assertThat(requests).hasValue(0);
    }

    @Test
    void resolvePermissions_cachesWithinTtl() {
        RolePermissionResolver resolver = resolver(Duration.ofMinutes(10));

        resolver.resolvePermissions(List.of("ADMIN"));
        resolver.resolvePermissions(List.of("ADMIN"));
        resolver.resolvePermissions(List.of("VIEWER"));

        assertThat(requests).hasValue(1);
    }

    @Test
    void resolvePermissions_failClosedWhenNeverLoaded() {
        failing.set(true);
        RolePermissionResolver resolver = resolver(Duration.ofMinutes(10));

        assertThat(resolver.resolvePermissions(List.of("ADMIN"))).isEmpty();
        assertThat(resolver.isReady()).isFalse();
    }

    @Test
    void resolvePermissions_keepsLastGoodMapWhenRefreshFails() {
        RolePermissionResolver resolver = resolver(Duration.ZERO);
        assertThat(resolver.resolvePermissions(List.of("ADMIN"))).isNotEmpty();

        failing.set(true);

        assertThat(resolver.resolvePermissions(List.of("ADMIN")))
                .containsExactlyInAnyOrder("CI_REGISTRATION:CREATE", "CI_DEMAND:LIST");
        assertThat(resolver.isReady()).isTrue();
    }

    @Test
    void resolvePermissions_keepsLastGoodMapWhenResponseIsEmpty() {
        RolePermissionResolver resolver = resolver(Duration.ZERO);
        assertThat(resolver.resolvePermissions(List.of("ADMIN"))).isNotEmpty();

        body.set("{}");

        assertThat(resolver.resolvePermissions(List.of("ADMIN"))).isNotEmpty();
    }

    @Test
    void resolvePermissions_backsOffAfterFailureInsteadOfRetryingEveryRequest() {
        failing.set(true);
        RolePermissionResolver resolver = resolver(Duration.ofMinutes(10));

        resolver.resolvePermissions(List.of("ADMIN"));
        resolver.resolvePermissions(List.of("ADMIN"));
        resolver.resolvePermissions(List.of("ADMIN"));

        assertThat(requests).hasValue(1);
    }
}
