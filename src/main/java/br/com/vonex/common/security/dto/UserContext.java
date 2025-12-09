package br.com.vonex.common.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserContext {
    private Long userId;
    private String login;
    private String name;
    private List<String> roles;
    private List<String> permissions;

    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    public boolean hasAnyPermission(String... permissions) {
        if (this.permissions == null) return false;
        for (String perm : permissions) {
            if (this.permissions.contains(perm)) return true;
        }
        return false;
    }

    public boolean hasAllPermissions(String... permissions) {
        if (this.permissions == null) return false;
        for (String perm : permissions) {
            if (!this.permissions.contains(perm)) return false;
        }
        return true;
    }

    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    public boolean isAdmin() {
        return hasRole("ADMIN");
    }
}