package br.com.vonex.common.security.service;

import br.com.vonex.common.security.dto.UserContext;
import br.com.vonex.common.security.exception.InvalidTokenException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

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
            
            return UserContext.builder()
                    .userId(jwt.getClaim("userId").asLong())
                    .login(jwt.getClaim("login").asString())
                    .name(jwt.getClaim("name").asString())
                    .roles(jwt.getClaim("roles").asList(String.class))
                    .permissions(jwt.getClaim("permissions").asList(String.class))
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
}