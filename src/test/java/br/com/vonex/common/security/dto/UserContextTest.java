package br.com.vonex.common.security.dto;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserContextTest {

    @Test
    void isCustomerScoped_null_defaultsTrue() {
        assertTrue(UserContext.builder().build().isCustomerScoped());
    }

    @Test
    void isCustomerScoped_true() {
        assertTrue(UserContext.builder().customerScoped(true).build().isCustomerScoped());
    }

    @Test
    void isCustomerScoped_false() {
        assertFalse(UserContext.builder().customerScoped(false).build().isCustomerScoped());
    }

    @Test
    void hasCommercialScope_agentsPresent_true() {
        assertTrue(UserContext.builder().commercialAgentIds(List.of(1L)).build().hasCommercialScope());
    }

    @Test
    void hasCommercialScope_afterSalesPresent_true() {
        assertTrue(UserContext.builder().afterSalesIds(List.of(2L)).build().hasCommercialScope());
    }

    @Test
    void hasCommercialScope_bothEmpty_false() {
        assertFalse(UserContext.builder().build().hasCommercialScope());
    }
}
