package br.com.vonex.common.security.service;

import br.com.vonex.common.security.dto.*;
import br.com.vonex.common.security.exception.InvalidTokenException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

import java.util.*;

@Slf4j
public class JwtTokenValidator {

    private final Algorithm algorithm;

    public JwtTokenValidator(@Value("${security.secretKey}") String secret) {
        this.algorithm = Algorithm.HMAC256(secret);
    }

    public UserContext validateAndExtractContext(String token) {
        try {
            DecodedJWT jwt = JWT.require(algorithm)
                    .withIssuer("auth")
                    .build()
                    .verify(token);

            Long userId = jwt.getClaim("userId").asLong();
            String login = jwt.getClaim("login").asString();
            String name = jwt.getClaim("name").asString();
            List<String> roles = jwt.getClaim("roles").asList(String.class);
            List<String> permissions = jwt.getClaim("permissions").asList(String.class);

            Claim orgContextClaim = jwt.getClaim("organizationalContext");

            List<ClientPortfolioDTO> portfolios = Collections.emptyList();
            List<TeamDTO> teams = Collections.emptyList();
            List<SalesChannelDTO> salesChannels = Collections.emptyList();
            List<SalesSegmentDTO> salesSegments = Collections.emptyList();

            List<Long> commercialAgentIds = Collections.emptyList();
            List<Long> afterSalesIds = Collections.emptyList();

            if (!orgContextClaim.isNull()) {
                try {
                    Map<String, Object> orgContext = orgContextClaim.asMap();

                    if (orgContext.containsKey("portfolios")) {
                        portfolios = parsePortfolios((List<Map<String, Object>>) orgContext.get("portfolios"));
                    }

                    if (orgContext.containsKey("teams")) {
                        teams = parseTeams((List<Map<String, Object>>) orgContext.get("teams"));
                    }

                    if (orgContext.containsKey("salesChannels")) {
                        salesChannels = parseSalesChannels((List<Map<String, Object>>) orgContext.get("salesChannels"));
                    }

                    if (orgContext.containsKey("salesSegments")) {
                        salesSegments = parseSalesSegments((List<Map<String, Object>>) orgContext.get("salesSegments"));
                    }

                    if (orgContext.containsKey("commercialAgentIds")) {
                        commercialAgentIds = parseLongList(orgContext.get("commercialAgentIds"));
                    }

                    if (orgContext.containsKey("afterSalesIds")) {
                        afterSalesIds = parseLongList(orgContext.get("afterSalesIds"));
                    }

                    log.debug("Extracted organizational context for user {}: {} portfolios, {} teams, {} agents, {} after-sales",
                            userId, portfolios.size(), teams.size(), commercialAgentIds.size(), afterSalesIds.size());

                } catch (Exception e) {
                    log.warn("Error parsing organizational context from token: {}", e.getMessage());
                }
            }

            return UserContext.builder()
                    .userId(userId)
                    .login(login)
                    .name(name)
                    .roles(roles != null ? roles : Collections.emptyList())
                    .permissions(permissions != null ? permissions : Collections.emptyList())
                    .portfolios(portfolios)
                    .teams(teams)
                    .salesChannels(salesChannels)
                    .salesSegments(salesSegments)
                    .commercialAgentIds(commercialAgentIds)
                    .afterSalesIds(afterSalesIds)
                    .build();

        } catch (JWTVerificationException e) {
            log.error("Token inválido: {}", e.getMessage());
            throw new InvalidTokenException("Token JWT inválido ou expirado", e);
        }
    }

    public String extractTokenFromHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new InvalidTokenException("Header Authorization ausente ou inválido");
        }
        return authorizationHeader.substring(7);
    }

    private List<ClientPortfolioDTO> parsePortfolios(List<Map<String, Object>> portfoliosList) {
        if (portfoliosList == null || portfoliosList.isEmpty()) {
            return Collections.emptyList();
        }

        List<ClientPortfolioDTO> portfolios = new ArrayList<>();
        for (Map<String, Object> p : portfoliosList) {
            try {
                portfolios.add(ClientPortfolioDTO.builder()
                        .id(getLongValue(p.get("id")))
                        .code((String) p.get("code"))
                        .name((String) p.get("name"))
                        .accessLevel((String) p.get("accessLevel"))
                        .build());
            } catch (Exception e) {
                log.warn("Error parsing portfolio: {}", e.getMessage());
            }
        }
        return portfolios;
    }

    private List<TeamDTO> parseTeams(List<Map<String, Object>> teamsList) {
        if (teamsList == null || teamsList.isEmpty()) {
            return Collections.emptyList();
        }

        List<TeamDTO> teams = new ArrayList<>();
        for (Map<String, Object> t : teamsList) {
            try {
                teams.add(TeamDTO.builder()
                        .id(getLongValue(t.get("id")))
                        .code((String) t.get("code"))
                        .name((String) t.get("name"))
                        .teamType((String) t.get("teamType"))
                        .memberRole((String) t.get("memberRole"))
                        .isLeader(getBooleanValue(t.get("isLeader")))
                        .build());
            } catch (Exception e) {
                log.warn("Error parsing team: {}", e.getMessage());
            }
        }
        return teams;
    }

    private List<SalesChannelDTO> parseSalesChannels(List<Map<String, Object>> channelsList) {
        if (channelsList == null || channelsList.isEmpty()) {
            return Collections.emptyList();
        }

        List<SalesChannelDTO> channels = new ArrayList<>();
        for (Map<String, Object> c : channelsList) {
            try {
                channels.add(SalesChannelDTO.builder()
                        .id(getLongValue(c.get("id")))
                        .code((String) c.get("code"))
                        .name((String) c.get("name"))
                        .channelType((String) c.get("channelType"))
                        .build());
            } catch (Exception e) {
                log.warn("Error parsing sales channel: {}", e.getMessage());
            }
        }
        return channels;
    }

    private List<SalesSegmentDTO> parseSalesSegments(List<Map<String, Object>> segmentsList) {
        if (segmentsList == null || segmentsList.isEmpty()) {
            return Collections.emptyList();
        }

        List<SalesSegmentDTO> segments = new ArrayList<>();
        for (Map<String, Object> s : segmentsList) {
            try {
                segments.add(SalesSegmentDTO.builder()
                        .id(getLongValue(s.get("id")))
                        .code((String) s.get("code"))
                        .name((String) s.get("name"))
                        .segmentType((String) s.get("segmentType"))
                        .build());
            } catch (Exception e) {
                log.warn("Error parsing sales segment: {}", e.getMessage());
            }
        }
        return segments;
    }

    private Long getLongValue(Object value) {
        if (value == null) return null;
        if (value instanceof Long) return (Long) value;
        if (value instanceof Integer) return ((Integer) value).longValue();
        if (value instanceof Number) return ((Number) value).longValue();
        return null;
    }

    private Boolean getBooleanValue(Object value) {
        if (value == null) return false;
        if (value instanceof Boolean) return (Boolean) value;
        return false;
    }

    private List<Long> parseLongList(Object value) {
        if (value == null) {
            return Collections.emptyList();
        }

        if (value instanceof List<?> list) {
            return list.stream()
                    .filter(Objects::nonNull)
                    .map(this::getLongValue)
                    .filter(Objects::nonNull)
                    .toList();
        }

        return Collections.emptyList();
    }
}