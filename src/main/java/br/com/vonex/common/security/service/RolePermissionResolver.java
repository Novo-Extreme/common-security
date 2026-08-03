package br.com.vonex.common.security.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Resolve as permissões efetivas de um usuário a partir das suas roles, consultando o access-control
 * e mantendo o mapa em cache.
 *
 * <p>Existe para tirar o claim {@code permissions} do JWT: o token do admin carregava ~290 permissões
 * e estourava o limite de header do Tomcat. As roles são poucas e estáveis, então a lista efetiva
 * pode ser resolvida no servidor.
 *
 * <p><b>Fail-closed:</b> enquanto não houver um mapa carregado, resolve para conjunto vazio — quem
 * chama nega o acesso. Uma vez carregado, uma falha de refresh mantém o último mapa bom em vez de
 * derrubar a autorização de todo mundo.
 */
@Slf4j
public class RolePermissionResolver {

    private static final Duration FAILURE_BACKOFF = Duration.ofSeconds(30);
    private static final ParameterizedTypeReference<Map<String, Set<String>>> ROLE_PERMISSIONS_TYPE =
            new ParameterizedTypeReference<>() {
            };

    private final WebClient accessControlWebClient;
    private final Duration ttl;
    private final AtomicReference<Snapshot> snapshot = new AtomicReference<>(Snapshot.empty());
    private final ReentrantLock refreshLock = new ReentrantLock();

    public RolePermissionResolver(WebClient accessControlWebClient, Duration ttl) {
        this.accessControlWebClient = accessControlWebClient;
        this.ttl = ttl;
    }

    /**
     * União das permissões de todas as roles informadas. Conjunto vazio se o cache ainda não tem um
     * mapa válido — o chamador deve tratar isso como "negar".
     */
    public Set<String> resolvePermissions(Collection<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return Collections.emptySet();
        }

        Map<String, Set<String>> rolePermissions = currentMap();
        if (rolePermissions.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> effective = new LinkedHashSet<>();
        for (String role : roles) {
            Set<String> permissions = rolePermissions.get(role);
            if (permissions == null) {
                log.warn("Role {} not present in the role->permissions map", role);
                continue;
            }
            effective.addAll(permissions);
        }

        return effective;
    }

    /** Indica se há um mapa carregado. Útil para distinguir "sem permissão" de "cache indisponível". */
    public boolean isReady() {
        return !currentMap().isEmpty();
    }

    private Map<String, Set<String>> currentMap() {
        Snapshot current = snapshot.get();
        if (!current.needsRefresh(ttl)) {
            return current.rolePermissions();
        }

        if (!refreshLock.tryLock()) {
            // outra thread já está atualizando: seguimos com o que temos em vez de enfileirar
            return current.rolePermissions();
        }

        try {
            // outra thread pode ter atualizado enquanto esperávamos o lock
            current = snapshot.get();
            if (!current.needsRefresh(ttl)) {
                return current.rolePermissions();
            }
            return refresh(current);
        } finally {
            refreshLock.unlock();
        }
    }

    private Map<String, Set<String>> refresh(Snapshot current) {
        try {
            Map<String, Set<String>> fetched = accessControlWebClient.get()
                    .uri("/api/v1/roles/permissions")
                    .retrieve()
                    .bodyToMono(ROLE_PERMISSIONS_TYPE)
                    .block();

            if (fetched == null || fetched.isEmpty()) {
                log.error("access-control returned an empty role->permissions map; keeping previous snapshot");
                snapshot.set(current.withFailure());
                return current.rolePermissions();
            }

            snapshot.set(Snapshot.loaded(fetched));
            log.info("Loaded role->permissions map for {} roles", fetched.size());
            return fetched;

        } catch (Exception e) {
            if (current.rolePermissions().isEmpty()) {
                log.error("Failed to load role->permissions map and there is no cached copy; "
                        + "permission checks will be denied until access-control responds: {}", e.getMessage());
            } else {
                log.warn("Failed to refresh role->permissions map, keeping the last good copy: {}", e.getMessage());
            }
            snapshot.set(current.withFailure());
            return current.rolePermissions();
        }
    }

    /**
     * @param rolePermissions último mapa bom (vazio enquanto nunca carregou)
     * @param loadedAt        quando o mapa foi carregado
     * @param failedAt        quando a última tentativa falhou, para não repetir a cada request
     */
    private record Snapshot(Map<String, Set<String>> rolePermissions, Instant loadedAt, Instant failedAt) {

        static Snapshot empty() {
            return new Snapshot(Collections.emptyMap(), Instant.EPOCH, Instant.EPOCH);
        }

        static Snapshot loaded(Map<String, Set<String>> rolePermissions) {
            return new Snapshot(Map.copyOf(rolePermissions), Instant.now(), Instant.EPOCH);
        }

        Snapshot withFailure() {
            return new Snapshot(rolePermissions, loadedAt, Instant.now());
        }

        boolean needsRefresh(Duration ttl) {
            Instant now = Instant.now();
            if (now.isBefore(failedAt.plus(FAILURE_BACKOFF))) {
                return false;
            }
            return rolePermissions.isEmpty() || now.isAfter(loadedAt.plus(ttl));
        }
    }
}
