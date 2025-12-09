package br.com.vonex.common.security.service;

import br.com.vonex.common.security.dto.UserContext;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class PermissionValidationService {
    
    public boolean hasPermission(UserContext ctx, String[] required, boolean requireAll) {
        if (ctx == null) {
            log.warn("UserContext é null");
            return false;
        }
        
        if (required == null || required.length == 0) {
            return true;
        }
        
        if (ctx.isAdmin()) {
            log.debug("Usuário {} é ADMIN, permitindo acesso", ctx.getLogin());
            return true;
        }
        
        boolean hasAccess = requireAll 
            ? ctx.hasAllPermissions(required)
            : ctx.hasAnyPermission(required);
        
        if (!hasAccess) {
            log.warn("Usuário {} sem permissão: {}", ctx.getLogin(), String.join(", ", required));
        }
        
        return hasAccess;
    }
}