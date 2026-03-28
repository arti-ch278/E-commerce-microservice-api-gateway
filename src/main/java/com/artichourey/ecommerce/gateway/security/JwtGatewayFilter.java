package com.artichourey.ecommerce.gateway.security;

import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import reactor.core.publisher.Mono;
import org.springframework.util.AntPathMatcher;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class JwtGatewayFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtGatewayFilter.class);

    private final JwtUtil jwtUtil;
    private final JwtConfig jwtConfig;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtGatewayFilter(JwtUtil jwtUtil, JwtConfig jwtConfig) {
        this.jwtUtil = jwtUtil;
        this.jwtConfig = jwtConfig;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        HttpMethod methodEnum = exchange.getRequest().getMethod();
        String method = (methodEnum != null) ? methodEnum.name() : "";

        log.info("Incoming Request: {} {}", method, path);

        //  Swagger/static bypass
        if (isSwaggerOrStaticPath(path)) {
            log.info("Swagger/Static allowed: {}", path);
            return chain.filter(exchange);
        }

        // Public URLs bypass (login/register)
        if (isPublicUrl(path)) {
            log.info("Public URL allowed: {}", path);
            return chain.filter(exchange);
        }

        // Authorization header check
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header for path: {}", path);
            return unauthorized(exchange);
        }

        String token = authHeader.substring(7);

        // Validate token
        if (!jwtUtil.validateToken(token)) {
            log.warn("Invalid JWT token for path: {}", path);
            return unauthorized(exchange);
        }

        String role = jwtUtil.getRole(token);
        String userId = jwtUtil.getUserId(token);

        // Normalize role
        if (role != null && !role.startsWith("ROLE_")) {
            role = "ROLE_" + role;
        }

        log.info("Token valid | UserId: {} | Role: {}", userId, role);

        //  Role-based authorization
        if (!isAuthorized(role, path, method)) {
            log.warn("Forbidden | Role {} not allowed for {} {}", role, method, path);
            return forbidden(exchange);
        }

        log.info("Authorized access granted for {} {}", method, path);

        // Pass user info to microservice
        ServerHttpRequest modifiedRequest = exchange.getRequest()
                .mutate()
                .header("X-User-Id", userId)
                .header("X-User-Role", role)
                .build();

        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    // Swagger + static resources + proxied API docs
    private boolean isSwaggerOrStaticPath(String path) {
        return pathMatcher.match("/swagger-ui/**", path)
                || pathMatcher.match("/swagger-ui.html", path)
                || pathMatcher.match("/v3/api-docs/**", path)
                || pathMatcher.match("/webjars/**", path)
                || pathMatcher.match("/swagger-resources/**", path)
                || pathMatcher.match("/favicon.ico", path)
                || pathMatcher.match("/api/*/v3/api-docs/**", path); // Allow proxied microservice docs
    }

    private boolean isPublicUrl(String path) {
        List<String> publicUrls = jwtConfig.getPublicUrls();
        if (publicUrls == null) return false;

        boolean match = publicUrls.stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));

        if (match) {
            log.debug("Matched public URL pattern for: {}", path);
        }

        return match;
    }

    private boolean isAuthorized(String role, String path, String method) {
        Map<String, Map<String, List<String>>> rolePermissions = jwtConfig.getRolePermissions();
        if (rolePermissions == null) return false;

        Map<String, List<String>> permissions = rolePermissions.get(role);
        if (permissions == null) return false;

        List<String> allowedPaths = permissions.get(method);
        if (allowedPaths == null) return false;

        return allowedPaths.stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        log.warn("Unauthorized request | Method: {} | Path: {} | Reason: Invalid or missing JWT",
                request.getMethod(),
                request.getURI().getPath()
        );

        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = """
            {
              "status": 401,
              "error": "Unauthorized",
              "message": "Invalid or missing JWT token"
            }
            """;

        DataBuffer buffer = response.bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));

        return response.writeWith(Mono.just(buffer));
    }
   
    private Mono<Void> forbidden(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        log.warn("Forbidden request | Method: {} | Path: {} | Reason: Role not authorized",
                request.getMethod(),
                request.getURI().getPath()
        );

        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = """
            {
              "status": 403,
              "error": "Forbidden",
              "message": "Access denied for this resource"
            }
            """;

        DataBuffer buffer = response.bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8));

        return response.writeWith(Mono.just(buffer));
    }
    @Override
    public int getOrder() {
        return -1; // Run before other filters
    }
}
