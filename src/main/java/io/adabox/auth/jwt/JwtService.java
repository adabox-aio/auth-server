package io.adabox.auth.jwt;

import io.adabox.auth.components.SecurityCipher;
import io.adabox.auth.config.ConfigProperties;
import io.adabox.auth.services.UserDetailsImpl;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

@Slf4j
@Component
public class JwtService {

    private final ConfigProperties configProperties;
    private final SecurityCipher securityCipher;

    @Autowired
    public JwtService(ConfigProperties configProperties,SecurityCipher securityCipher) {
        this.configProperties = configProperties;
        this.securityCipher = securityCipher;
    }

    public String generateJwtToken(Authentication authentication) {
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + configProperties.getJwtExpirationMs()))
                .signWith(SignatureAlgorithm.HS512, configProperties.getJwtSecretKey())
                .compact();
    }

    public String getStakeKeyFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(configProperties.getJwtSecretKey()).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(configProperties.getJwtSecretKey()).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    public String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return securityCipher.decrypt(headerAuth.substring(7));
        }
        return null;
    }
}
