package com.fikua.dss.health;

import com.fikua.dss.IntegrationTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class CertificateHealthIndicatorTest extends IntegrationTestBase {

    @Autowired MockMvc mockMvc;
    @Autowired CertificateHealthIndicator indicator;

    @Test
    void healthAnswersTheHealthJsonFormatWithStatusesOnly() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", containsString("application/health+json")))
                .andExpect(jsonPath("$.status").value("pass"))
                .andExpect(jsonPath("$.checks['certificate:status'][0].status").value("pass"))
                .andExpect(content().string(not(containsString("keyAlgorithm"))))
                .andExpect(content().string(not(containsString("mock-client"))));
    }

    @Test
    void indicatorReturnsUpDirectly() {
        var health = indicator.health();
        assertEquals(Status.UP, health.getStatus());
    }

    @Test
    void statusMapping() {
        assertEquals("pass", HealthController.map(Status.UP));
        assertEquals("fail", HealthController.map(Status.DOWN));
        assertEquals("fail", HealthController.map(Status.OUT_OF_SERVICE));
        assertEquals("warn", HealthController.map(Status.UNKNOWN));
    }
}
