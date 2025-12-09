package br.com.vonex.common.security.service;

import br.com.vonex.common.security.dto.UserContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Collections;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class OrganizationalFilterService {

    private final WebClient accessControlWebClient;

    public List<Long> getAccessibleAccountIds(UserContext userContext) {
        if (userContext.isAdmin()) {
            log.debug("User {} is admin, no filtering needed", userContext.getUserId());
            return null;
        }

        if (userContext.getPortfolios().isEmpty()) {
            log.warn("User {} has no portfolios, returning empty list", userContext.getUserId());
            return Collections.emptyList();
        }

        try {
            List<Long> accountIds = accessControlWebClient.get()
                    .uri("/api/v1/access-control/users/{userId}/accessible-accounts", 
                        userContext.getUserId())
                    .retrieve()
                    .bodyToFlux(Long.class)
                    .collectList()
                    .block();

            log.debug("User {} has access to {} accounts", userContext.getUserId(), 
                accountIds != null ? accountIds.size() : 0);

            return accountIds != null ? accountIds : Collections.emptyList();

        } catch (Exception e) {
            log.error("Error fetching accessible accounts for user {}: {}", 
                userContext.getUserId(), e.getMessage());
            return Collections.emptyList();
        }
    }
}