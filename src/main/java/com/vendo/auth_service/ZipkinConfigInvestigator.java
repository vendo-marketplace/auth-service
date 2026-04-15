package com.vendo.auth_service;

import brave.Tracer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class ZipkinConfigInvestigator implements CommandLineRunner {

    @Value("${management.zipkin.tracing.endpoint:NOT_FOUND}")
    private String zipkinEndpoint;

    @Autowired(required = false)
    private Tracer tracer;

    @Override
    public void run(String... args) throws Exception {
        log.info("=========================================================");
        log.info("ZIPKIN CONFIGURATION");
        log.info("Spring Boot property: {}", zipkinEndpoint);
        log.info("Micrometer Tracer Bean: {}", tracer != null ? "FOUND (" + tracer.getClass().getSimpleName() + ")" : "NULL (Tracing failed to start!)");
        log.info("=========================================================");
    }
}
