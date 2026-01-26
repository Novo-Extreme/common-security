package br.com.vonex.common.security.config.filter;

import br.com.vonex.common.security.dto.UserContext;
import br.com.vonex.common.security.service.JwtTokenValidator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class SecurityFilter extends OncePerRequestFilter {

    private final JwtTokenValidator jwtTokenValidator;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            log.debug("OPTIONS request - skipping authentication");
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                String token = jwtTokenValidator.extractTokenFromHeader(authHeader);
                UserContext userContext = jwtTokenValidator.validateAndExtractContext(token);

                var authorities = userContext.getPermissions().stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                var authentication = new UsernamePasswordAuthenticationToken(
                        userContext.getLogin(),
                        null,
                        authorities
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("User authenticated: {}", userContext.getLogin());

            } catch (Exception e) {
                log.error("Error authenticating user: {}", e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }
}