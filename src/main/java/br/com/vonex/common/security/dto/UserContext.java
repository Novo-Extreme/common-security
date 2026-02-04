package br.com.vonex.common.security.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserContext {
    private Long userId;
    private String login;
    private String name;
    private List<String> roles;
    private List<String> permissions;

    private List<SalesChannelDTO> salesChannels;
    private List<SalesSegmentDTO> salesSegments;
    private List<ClientPortfolioDTO> portfolios;
    private List<TeamDTO> teams;

    private List<Long> commercialAgentIds;
    private List<Long> afterSalesIds;

    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    public boolean hasAnyPermission(String... permissions) {
        if (this.permissions == null) return false;
        for (String perm : permissions) {
            if (this.permissions.contains(perm)) return true;
        }
        return false;
    }

    public boolean hasAllPermissions(String... permissions) {
        if (this.permissions == null) return false;
        for (String perm : permissions) {
            if (!this.permissions.contains(perm)) return false;
        }
        return true;
    }

    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    public boolean isAdmin() {
        return hasRole("ADMIN");
    }

    public List<Long> getPortfolioIds() {
        if (portfolios == null || portfolios.isEmpty()) {
            return Collections.emptyList();
        }
        return portfolios.stream()
                .map(ClientPortfolioDTO::getId)
                .collect(Collectors.toList());
    }

    public List<Long> getTeamIds() {
        if (teams == null || teams.isEmpty()) {
            return Collections.emptyList();
        }
        return teams.stream()
                .map(TeamDTO::getId)
                .collect(Collectors.toList());
    }

    public List<Long> getSalesChannelIds() {
        if (salesChannels == null || salesChannels.isEmpty()) {
            return Collections.emptyList();
        }
        return salesChannels.stream()
                .map(SalesChannelDTO::getId)
                .collect(Collectors.toList());
    }

    public List<Long> getSalesSegmentIds() {
        if (salesSegments == null || salesSegments.isEmpty()) {
            return Collections.emptyList();
        }
        return salesSegments.stream()
                .map(SalesSegmentDTO::getId)
                .collect(Collectors.toList());
    }

    public boolean hasPortfolio(Long portfolioId) {
        if (portfolioId == null) return false;
        return portfolios != null &&
                portfolios.stream().anyMatch(p -> portfolioId.equals(p.getId()));
    }

    public boolean hasTeam(Long teamId) {
        if (teamId == null) return false;
        return teams != null &&
                teams.stream().anyMatch(t -> teamId.equals(t.getId()));
    }

    public boolean hasSalesChannel(Long channelId) {
        if (channelId == null) return false;
        return salesChannels != null &&
                salesChannels.stream().anyMatch(c -> channelId.equals(c.getId()));
    }

    public boolean hasSalesSegment(Long segmentId) {
        if (segmentId == null) return false;
        return salesSegments != null &&
                salesSegments.stream().anyMatch(s -> segmentId.equals(s.getId()));
    }

    public boolean hasFullAccessToPortfolio(Long portfolioId) {
        if (portfolioId == null || portfolios == null) return false;
        return portfolios.stream()
                .anyMatch(p -> portfolioId.equals(p.getId()) &&
                        "FULL".equals(p.getAccessLevel()));
    }

    public boolean isTeamLeader() {
        if (teams == null || teams.isEmpty()) return false;
        return teams.stream().anyMatch(t -> Boolean.TRUE.equals(t.getIsLeader()));
    }

    public boolean isLeaderOfTeam(Long teamId) {
        if (teamId == null || teams == null) return false;
        return teams.stream()
                .anyMatch(t -> teamId.equals(t.getId()) &&
                        Boolean.TRUE.equals(t.getIsLeader()));
    }

    public boolean hasOrganizationalContext() {
        return (portfolios != null && !portfolios.isEmpty()) ||
                (teams != null && !teams.isEmpty()) ||
                (salesChannels != null && !salesChannels.isEmpty()) ||
                (salesSegments != null && !salesSegments.isEmpty());
    }

    public List<Long> getCommercialAgentIds() {
        return commercialAgentIds != null ? commercialAgentIds : Collections.emptyList();
    }

    public List<Long> getAfterSalesIds() {
        return afterSalesIds != null ? afterSalesIds : Collections.emptyList();
    }

    public boolean hasCommercialAgent(Long commercialAgentId) {
        if (commercialAgentId == null) return false;
        return commercialAgentIds != null && commercialAgentIds.contains(commercialAgentId);
    }

    public boolean hasAfterSales(Long afterSalesId) {
        if (afterSalesId == null) return false;
        return afterSalesIds != null && afterSalesIds.contains(afterSalesId);
    }
}