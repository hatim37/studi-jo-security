package com.ecom.security.config;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwtConfig {

    public JwtConfig(RsakeysConfig rsakeysConfig) {
        this.rsakeysConfig = rsakeysConfig;
    }

    private RsakeysConfig rsakeysConfig;

    @Bean
    public PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder();}


    // ─── TECHNICAL TOKENS ─────────────────────────────────────────────────────────
    //Génère clé RSA pour JWT inter-services
    @Bean
    @Qualifier("techRsaKey")
    public RSAKey techRsaKey() {
        try {
            var gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            var kp = gen.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                    .privateKey(kp.getPrivate())
                    .keyID("tech-key")
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Impossible de générer la clé RSA", e);
        }
    }


    //Expose clé public pour api inter-services
    @Bean
    @Qualifier("techJwkSource")
    public JWKSource<SecurityContext> techJwkSource(@Qualifier("techRsaKey") RSAKey techRsaKey) {
        return new ImmutableJWKSet<>(new JWKSet((JWK) techRsaKey));
    }


    //Encode token inter-services
    @Bean
    @Primary
    @Qualifier("techJwtEncoder")
    public JwtEncoder techJwtEncoder(@Qualifier("techJwkSource") JWKSource<SecurityContext> techJwkSource) {
        return new NimbusJwtEncoder(techJwkSource);
    }


    public JwtDecoder techJwtDecoder(@Qualifier("techRsaKey") RSAKey techRsaKey) {
        try {
            return NimbusJwtDecoder
                    .withPublicKey(techRsaKey.toRSAPublicKey())
                    .build();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }


}
