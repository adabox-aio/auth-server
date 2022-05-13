package io.adabox.auth.components;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    private static final String tokenCookieName = "X-AUTH";
    private final SecurityCipher securityCipher;

    @Autowired
    public CookieUtil(SecurityCipher securityCipher) {
        this.securityCipher = securityCipher;
    }

    public HttpCookie createAccessTokenCookie(String token, Long duration) {
        return ResponseCookie.from(tokenCookieName, securityCipher.encrypt(token))
                .maxAge(duration)
                .httpOnly(true)
                .path("/")
                .secure(true)
                .build();
    }
}
