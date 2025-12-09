package br.com.vonex.common.security.interceptor;

import br.com.vonex.common.security.annotation.RequiresPermission;
import br.com.vonex.common.security.dto.UserContext;
import br.com.vonex.common.security.exception.InvalidTokenException;
import br.com.vonex.common.security.exception.PermissionDeniedException;
import br.com.vonex.common.security.service.JwtTokenValidator;
import br.com.vonex.common.security.service.PermissionValidationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

@Slf4j
@RequiredArgsConstructor
public class PermissionInterceptor implements HandlerInterceptor {

    private final JwtTokenValidator jwtValidator;
    private final PermissionValidationService permissionService;

    public static final String USER_CONTEXT_ATTRIBUTE = "userContext";

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {

        log.info("🔍 PermissionInterceptor triggered for: {} {}",
                request.getMethod(), request.getRequestURI());

        try {
            String authHeader = request.getHeader("Authorization");
            log.debug("📋 Authorization header: {}", authHeader != null ? "Present" : "Missing");

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = jwtValidator.extractTokenFromHeader(authHeader);
                log.debug("🔑 Token extracted, validating...");

                UserContext userContext = jwtValidator.validateAndExtractContext(token);

                request.setAttribute(USER_CONTEXT_ATTRIBUTE, userContext);
                log.info("✅ UserContext populated for user: {} (userId: {}, portfolios: {})",
                        userContext.getLogin(),
                        userContext.getUserId(),
                        userContext.getPortfolios().size());
            } else {
                log.warn("⚠️ No Bearer token found in Authorization header");
            }
        } catch (InvalidTokenException e) {
            log.error("❌ Invalid token: {}", e.getMessage());
        } catch (Exception e) {
            log.error("❌ Unexpected error extracting UserContext: {}", e.getMessage(), e);
        }

        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        RequiresPermission annotation = handlerMethod.getMethodAnnotation(RequiresPermission.class);
        if (annotation == null) {
            annotation = handlerMethod.getBeanType().getAnnotation(RequiresPermission.class);
        }

        if (annotation == null) {
            log.debug("✓ No @RequiresPermission annotation, allowing access");
            return true;
        }

        UserContext userContext = (UserContext) request.getAttribute(USER_CONTEXT_ATTRIBUTE);

        if (userContext == null) {
            log.warn("🚫 @RequiresPermission presente mas UserContext não encontrado");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        try {
            boolean hasPermission = permissionService.hasPermission(
                    userContext,
                    annotation.value(),
                    annotation.requireAll()
            );

            if (!hasPermission) {
                log.warn("🚫 Acesso negado: {} {} - User: {}",
                        request.getMethod(), request.getRequestURI(), userContext.getLogin());
                throw new PermissionDeniedException(annotation.message());
            }

            return true;

        } catch (PermissionDeniedException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
    }
}