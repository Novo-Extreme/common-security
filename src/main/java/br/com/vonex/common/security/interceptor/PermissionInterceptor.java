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
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }
        
        RequiresPermission annotation = handlerMethod.getMethodAnnotation(RequiresPermission.class);
        if (annotation == null) {
            annotation = handlerMethod.getBeanType().getAnnotation(RequiresPermission.class);
        }
        
        if (annotation == null) {
            return true;
        }
        
        try {
            String authHeader = request.getHeader("Authorization");
            String token = jwtValidator.extractTokenFromHeader(authHeader);
            UserContext userContext = jwtValidator.validateAndExtractContext(token);
            
            request.setAttribute(USER_CONTEXT_ATTRIBUTE, userContext);
            
            boolean hasPermission = permissionService.hasPermission(
                userContext, 
                annotation.value(), 
                annotation.requireAll()
            );
            
            if (!hasPermission) {
                log.warn("Acesso negado: {} {} - User: {}", 
                    request.getMethod(), request.getRequestURI(), userContext.getLogin());
                throw new PermissionDeniedException(annotation.message());
            }
            
            return true;
            
        } catch (InvalidTokenException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        } catch (PermissionDeniedException e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }
    }
}