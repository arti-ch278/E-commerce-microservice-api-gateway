package com.artichourey.ecommerce.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;
@Component
public class CustomRouteFilter extends AbstractGatewayFilterFactory<Object> {

    private final Logger log = LoggerFactory.getLogger(CustomRouteFilter.class);

    public CustomRouteFilter() {
        super(Object.class);
    }

    @Override
    public GatewayFilter apply(Object config) {

        return (exchange, chain) -> {

            log.info("Route Filter: Before routing");

            ServerHttpRequest modifiedRequest = exchange.getRequest()
                    .mutate()
                    .header("X-Route-Header", "Added-By-Gateway")
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build())
                    .then(Mono.fromRunnable(() ->
                            log.info("Route Filter: After routing")));
        };
    }
}