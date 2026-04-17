package com.artichourey.ecommerce.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class CustomGlobalFilter implements GlobalFilter {

    private final Logger log = LoggerFactory.getLogger(CustomGlobalFilter.class);

//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//
//        return chain.filter(exchange)
//                .doOnSubscribe(sub ->
//                        log.info("Global filter: request intercepted: {}",
//                                exchange.getRequest().getURI())
//                )
//                .doOnSuccess(aVoid ->
//                        log.info("Global filter: Response Completed")
//                );
//    }
    
   
        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

            return chain.filter(exchange)
                    .contextWrite(ctx -> ctx)
                    .doOnEach(signal -> {
                        if (!signal.isOnNext() && !signal.isOnComplete()) return;

                        log.info("Gateway request: {}",
                                exchange.getRequest().getURI());
                    })
                    .doFinally(signal ->
                            log.info("Gateway response completed")
                    );
        }
    }
