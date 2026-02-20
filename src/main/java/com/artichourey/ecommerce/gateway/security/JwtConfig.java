package com.artichourey.ecommerce.gateway.security;

import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {

	private List<String> publicUrls;
    private Map<String, Map<String, List<String>>> rolePermissions;

    public List<String> getPublicUrls() { return publicUrls; }
    public void setPublicUrls(List<String> publicUrls) { this.publicUrls = publicUrls; }

    public Map<String, Map<String, List<String>>> getRolePermissions() { return rolePermissions; }
    public void setRolePermissions(Map<String, Map<String, List<String>>> rolePermissions) {
        this.rolePermissions = rolePermissions;
    }
	
	
}
