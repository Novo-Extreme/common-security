package br.com.vonex.common.security.interceptor;

import br.com.vonex.common.security.annotation.RequiresPermission;
import br.com.vonex.common.security.dto.UserContext;
import br.com.vonex.common.security.exception.InvalidTokenException;
import br.com.vonex.common.security.exception.PermissionDeniedException;
import br.com.vonex.common.security.service.JwtTokenValidator;
import br.com.vonex.common.security.service.PermissionValidationService;
import br.com.vonex.common.security.service.RolePermissionResolver;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@Slf4j
public class PermissionInterceptor implements HandlerInterceptor {

    private final JwtTokenValidator jwtValidator;
    private final PermissionValidationService permissionService;
    private final RolePermissionResolver rolePermissionResolver;
    private final ObjectMapper objectMapper = createObjectMapper();

    public PermissionInterceptor(JwtTokenValidator jwtValidator,
                                 PermissionValidationService permissionService,
                                 RolePermissionResolver rolePermissionResolver) {
        this.jwtValidator = jwtValidator;
        this.permissionService = permissionService;
        this.rolePermissionResolver = rolePermissionResolver;
    }

    /** Sem resolver: mantém o comportamento anterior (só o claim do token). */
    public PermissionInterceptor(JwtTokenValidator jwtValidator,
                                 PermissionValidationService permissionService) {
        this(jwtValidator, permissionService, null);
    }

    public static final String USER_CONTEXT_ATTRIBUTE = "userContext";

    private static ObjectMapper createObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        return mapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {

        log.info("PermissionInterceptor triggered for: {} {}",
                request.getMethod(), request.getRequestURI());

        try {
            String authHeader = request.getHeader("Authorization");
            log.debug("Authorization header: {}", authHeader != null ? "Present" : "Missing");

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = jwtValidator.extractTokenFromHeader(authHeader);
                log.debug("Token extracted, validating...");

                UserContext userContext = jwtValidator.validateAndExtractContext(token);

                request.setAttribute(USER_CONTEXT_ATTRIBUTE, userContext);
                log.info("UserContext populated for user: {} (userId: {}, portfolios: {})",
                        userContext.getLogin(),
                        userContext.getUserId(),
                        userContext.getPortfolios().size());
            } else {
                log.warn("No Bearer token found in Authorization header");
            }
        } catch (InvalidTokenException e) {
            log.error("Invalid token: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Unexpected error extracting UserContext: {}", e.getMessage(), e);
        }

        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        RequiresPermission annotation = handlerMethod.getMethodAnnotation(RequiresPermission.class);
        if (annotation == null) {
            annotation = handlerMethod.getBeanType().getAnnotation(RequiresPermission.class);
        }

        if (annotation == null) {
            log.debug("No @RequiresPermission annotation, allowing access");
            return true;
        }

        UserContext userContext = (UserContext) request.getAttribute(USER_CONTEXT_ATTRIBUTE);

        if (userContext == null) {
            log.warn("@RequiresPermission present but UserContext not found");
            writeErrorResponse(response, request, HttpServletResponse.SC_UNAUTHORIZED,
                    "Não Autorizado", "Token de autenticação não encontrado ou inválido", null);
            return false;
        }

        if (userContext.isAdmin()) {
            log.debug("Admin user {} - bypassing permission check", userContext.getUserId());
            return true;
        }

        if (userContext.getPermissions() == null || userContext.getPermissions().isEmpty()) {
            // Token sem o claim 'permissions': resolve pelas roles. Se o claim vier (authentication
            // antigo), ele é usado como está — é o que permite o rollout gradual.
            resolvePermissionsFromRoles(userContext);
        }

        if (userContext.getPermissions() == null || userContext.getPermissions().isEmpty()) {
            log.warn("No permissions resolved for non-admin user {}. Required: {}",
                    userContext.getUserId(), String.join(", ", annotation.value()));
            writeErrorResponse(response, request, HttpServletResponse.SC_FORBIDDEN,
                    "Acesso Negado", "Permissões não disponíveis. Faça login novamente.", userContext);
            return false;
        }

        try {
            boolean hasPermission = permissionService.hasPermission(
                    userContext,
                    annotation.value(),
                    annotation.requireAll()
            );

            if (!hasPermission) {
                log.warn("Access denied: {} {} - User: {\"userId\":{},\"name\":\"{}\"}",
                        request.getMethod(), request.getRequestURI(),
                        userContext.getUserId(), userContext.getLogin());
                throw new PermissionDeniedException(annotation.message());
            }

            return true;

        } catch (PermissionDeniedException e) {
            String requiredPermissions = String.join(", ", annotation.value());
            String message = String.format("%s. Permissões requeridas: [%s]. Usuário: %s (ID: %d)",
                    e.getMessage(), requiredPermissions, userContext.getLogin(), userContext.getUserId());

            writeErrorResponse(response, request, HttpServletResponse.SC_FORBIDDEN,
                    "Acesso Negado", message, userContext);
            return false;
        }
    }

    private void resolvePermissionsFromRoles(UserContext userContext) {
        if (rolePermissionResolver == null) {
            return;
        }

        Set<String> resolved = rolePermissionResolver.resolvePermissions(userContext.getRoles());
        if (resolved.isEmpty()) {
            return;
        }

        userContext.setPermissions(new ArrayList<>(resolved));
        log.debug("Resolved {} permissions from roles {} for user {}",
                resolved.size(), userContext.getRoles(), userContext.getUserId());
    }

    private void writeErrorResponse(HttpServletResponse response, HttpServletRequest request,
                                    int status, String error, String message, UserContext userContext) {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> errorBody = new LinkedHashMap<>();
        errorBody.put("timestamp", LocalDateTime.now().toString());
        errorBody.put("status", status);
        errorBody.put("error", error);
        errorBody.put("message", message);
        errorBody.put("path", request.getRequestURI());

        if (userContext != null) {
            Map<String, Object> user = new LinkedHashMap<>();
            user.put("userId", userContext.getUserId());
            user.put("login", userContext.getLogin());
            user.put("admin", userContext.isAdmin());
            user.put("permissions", userContext.getPermissions());
            errorBody.put("user", user);
        }

        try {
            response.getWriter().write(objectMapper.writeValueAsString(errorBody));
        } catch (IOException ex) {
            log.error("Failed to write error response: {}", ex.getMessage());
        }
    }
}