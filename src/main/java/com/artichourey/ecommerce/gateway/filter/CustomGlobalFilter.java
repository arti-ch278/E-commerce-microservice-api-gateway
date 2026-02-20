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

	private final Logger log= LoggerFactory.getLogger(CustomGlobalFilter.class);
	
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
	 log.info("Global filter: request intercepted",exchange.getRequest());
	 return chain.filter(exchange).then(Mono.fromRunnable(()->{
		 log.info("global filter:Response Completed");
	 }));
		
	}

}
