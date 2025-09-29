package com.ecom.security.service;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
public class TokenMicroService {

    @Value("${security.service.url}")
    private String securityServiceUrl;
    private final JwtEncoder jwtEncoder;

    public TokenMicroService(@Qualifier("techJwtEncoder") JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public String tokenService(){
        Instant now = Instant.now();
        // Construction du JWT Claims
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(securityServiceUrl)
                .issuedAt(now)
                .expiresAt(now.plus(Duration.ofHours(1)))
                .subject("security-service")
                .claim("scope", "users:read users:write")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims))
                .getTokenValue();
    }
}
