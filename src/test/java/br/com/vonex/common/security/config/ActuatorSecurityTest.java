package br.com.vonex.common.security.config;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * T5 da trilha de seguranca: o SecurityFilterChain da lib liberava {@code /actuator/**} inteiro.
 * Agora so health (probes) e info sao publicos; o resto do actuator exige token.
 */
@WebMvcTest(controllers = ActuatorSecurityTestSupport.FakeActuatorController.class)
@ContextConfiguration(classes = {
        SecurityConfig.class,
        ActuatorSecurityTestSupport.Beans.class,
        ActuatorSecurityTestSupport.FakeActuatorController.class
})
class ActuatorSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @ParameterizedTest
    @ValueSource(strings = {
            "/actuator/health",
            "/actuator/health/liveness",
            "/actuator/health/readiness",
            "/actuator/info"
    })
    void healthAndInfo_arePublic(String path) throws Exception {
        mockMvc.perform(get(path)).andExpect(status().isOk());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/actuator/env",
            "/actuator/configprops",
            "/actuator/heapdump",
            "/actuator/loggers",
            "/actuator/metrics",
            "/actuator/prometheus"
    })
    void otherActuatorEndpoints_withoutToken_return401(String path) throws Exception {
        mockMvc.perform(get(path)).andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/actuator/env", "/actuator/metrics", "/actuator/prometheus"})
    void otherActuatorEndpoints_withValidToken_areAllowed(String path) throws Exception {
        mockMvc.perform(get(path).header("Authorization", ActuatorSecurityTestSupport.bearerToken()))
                .andExpect(status().isOk());
    }
}
