package com.artichourey.ecommerce.gateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;
@Component
public class CustomRouteFilter extends AbstractGatewayFilterFactory<Object> {
	
	private final Logger log= LoggerFactory.getLogger(CustomRouteFilter.class);

	public CustomRouteFilter()
	{
		super(Object.class);
	}	
	@Override
	public GatewayFilter apply(Object config) {
		// TODO Auto-generated method stub
		return (exchange,chain)->{
			log.info("Route filter: Before routing");
			exchange.getRequest().mutate().header("X-Route-Header", "Added-By-Gateway")
			.build();
			return chain.filter(exchange).then(Mono.fromRunnable(()->{
			log.info("Route Filter:After routing");
		}));
	};
	}
}
