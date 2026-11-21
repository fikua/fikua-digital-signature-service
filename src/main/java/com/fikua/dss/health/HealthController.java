package com.fikua.dss.health;

import org.springframework.boot.actuate.health.CompositeHealth;
import org.springframework.boot.actuate.health.HealthComponent;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.health.Status;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * GET /health in the format every Fikua service follows (fikua-docs
 * conv-observability.md, OBS-17; draft-inadarei-api-health-check-06):
 * {"status":"pass"|"warn"|"fail","checks":{"<component>:status":[{"status":...}]}},
 * 503 on fail. Built from the Actuator's aggregated health, but only component
 * names and statuses leave the service: the Actuator itself (with its details)
 * is on the internal management port, which Traefik does not route.
 */
@RestController
public class HealthController {

    static final MediaType HEALTH_JSON = MediaType.parseMediaType("application/health+json");

    private final HealthEndpoint healthEndpoint;

    public HealthController(HealthEndpoint healthEndpoint) {
        this.healthEndpoint = healthEndpoint;
    }

    @GetMapping(value = "/health", produces = "application/health+json")
    public ResponseEntity<Map<String, Object>> health() {
        HealthComponent health = healthEndpoint.health();
        String status = map(health.getStatus());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        if (health instanceof CompositeHealth composite && composite.getComponents() != null) {
            Map<String, List<Map<String, String>>> checks = new TreeMap<>();
            composite.getComponents().forEach((name, component) ->
                    checks.put(name + ":status", List.of(Map.of("status", map(component.getStatus())))));
            body.put("checks", checks);
        }
        return ResponseEntity.status("fail".equals(status) ? 503 : 200)
                .contentType(HEALTH_JSON)
                .cacheControl(CacheControl.noStore())
                .body(body);
    }

    static String map(Status status) {
        if (Status.UP.equals(status)) {
            return "pass";
        }
        if (Status.DOWN.equals(status) || Status.OUT_OF_SERVICE.equals(status)) {
            return "fail";
        }
        return "warn";
    }
}
