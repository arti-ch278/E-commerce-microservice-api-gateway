package com.artichourey.ecommerce.gateway.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;
import java.util.Map;

@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {

    private List<String> publicUrls;
    private Map<String, Map<String, List<String>>> rolePermissions;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public List<String> getPublicUrls() {
        return publicUrls;
    }

    public void setPublicUrls(List<String> publicUrls) {
        this.publicUrls = publicUrls;
    }

    public Map<String, Map<String, List<String>>> getRolePermissions() {
        return rolePermissions;
    }

    public void setRolePermissions(Map<String, Map<String, List<String>>> rolePermissions) {
        this.rolePermissions = rolePermissions;
    }

    /**
     * Check if path is in public URLs
     */
    public boolean isPublicUrl(String path) {
        if (publicUrls == null) return false;
        return publicUrls.stream().anyMatch(pattern -> pathMatcher.match(pattern, path));
    }
}