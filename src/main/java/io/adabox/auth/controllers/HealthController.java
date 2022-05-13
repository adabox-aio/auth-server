package io.adabox.auth.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {

    @PreAuthorize("permitAll()")
    @GetMapping("/keepAlive")
    public ResponseEntity<?> keepAlive() {
        return ResponseEntity.ok().build();
    }
}
