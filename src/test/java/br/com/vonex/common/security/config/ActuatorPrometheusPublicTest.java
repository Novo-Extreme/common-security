package br.com.vonex.common.security.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Com {@code security.actuator.prometheus-public=true} (servico raspado pelo Prometheus do cluster),
 * so o /actuator/prometheus passa a ser publico; env/heapdump/metrics continuam exigindo token.
 */
@WebMvcTest(
        controllers = ActuatorSecurityTestSupport.FakeActuatorController.class,
        properties = "security.actuator.prometheus-public=true"
)
@ContextConfiguration(classes = {
        SecurityConfig.class,
        ActuatorSecurityTestSupport.Beans.class,
        ActuatorSecurityTestSupport.FakeActuatorController.class
})
class ActuatorPrometheusPublicTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void prometheus_isPublic_whenFlagEnabled() throws Exception {
        mockMvc.perform(get("/actuator/prometheus")).andExpect(status().isOk());
    }

    @Test
    void healthStillPublic_whenFlagEnabled() throws Exception {
        mockMvc.perform(get("/actuator/health/liveness")).andExpect(status().isOk());
    }

    @Test
    void otherEndpoints_stillRequireToken_whenFlagEnabled() throws Exception {
        mockMvc.perform(get("/actuator/env")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/actuator/heapdump")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/actuator/metrics")).andExpect(status().isUnauthorized());
    }
}
