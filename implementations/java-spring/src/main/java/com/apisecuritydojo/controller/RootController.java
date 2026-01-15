package com.apisecuritydojo.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Root endpoints (/, /health).
 */
@RestController
public class RootController {

    @Value("${dojo.mode:challenge}")
    private String mode;

    @GetMapping("/")
    public Map<String, Object> root() {
        return Map.of(
            "name", "API Security Dojo",
            "version", "0.2.0",
            "mode", mode,
            "implementation", "Java/Spring Boot",
            "message", "Welcome to API Security Dojo - A deliberately vulnerable API"
        );
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "healthy", "implementation", "java-spring");
    }
}
