package com.fikua.dss.health;

import com.fikua.dss.IntegrationTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class CertificateHealthIndicatorTest extends IntegrationTestBase {

    @Autowired MockMvc mockMvc;
    @Autowired CertificateHealthIndicator indicator;

    @Test
    void actuatorHealthExposesCertificateComponentAsUp() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.components.certificate.status").value("UP"))
                .andExpect(jsonPath("$.components.certificate.details.keyAlgorithm").exists());
    }

    @Test
    void livenessProbeIsExposed() throws Exception {
        mockMvc.perform(get("/health/liveness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void readinessProbeIncludesCertificate() throws Exception {
        mockMvc.perform(get("/health/readiness"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void indicatorReturnsUpDirectly() {
        var health = indicator.health();
        assertEquals(Status.UP, health.getStatus());
    }

    @Test
    void actuatorInfoExposesAppName() throws Exception {
        mockMvc.perform(get("/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.app.name").value("fikua-digital-signature-service"));
    }
}
