package com.artichourey.ecommerce.gateway.config;

import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;

@Configuration
public class ReactorTracingConfig {

    @PostConstruct
    public void setup() {
        reactor.core.publisher.Hooks.enableAutomaticContextPropagation();
    }
}