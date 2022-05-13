package io.adabox.auth.controllers;

import io.adabox.auth.config.ConfigProperties;
import io.adabox.auth.repositories.models.User;
import io.adabox.auth.services.UserDetailsImpl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/users")
public class UsersController {

    private final ConfigProperties configProperties;
    private final PasswordEncoder passwordEncoder;

    public UsersController(ConfigProperties configProperties, PasswordEncoder passwordEncoder) {
        this.configProperties = configProperties;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_MODERATOR') or hasRole('ROLE_ADMIN')")
    public ResponseEntity<User> userAccess(@RequestParam("secret") String secret, Principal principal) {
        if (!passwordEncoder.matches(configProperties.getAppSecret(), secret)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(((UserDetailsImpl)((UsernamePasswordAuthenticationToken) principal).getPrincipal()).getUser());
    }
}
