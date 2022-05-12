package io.adabox.auth.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {

    @GetMapping("/keepAlive")
    public ResponseEntity<?> keepAlive() {
        return ResponseEntity.ok().build();
    }
}
