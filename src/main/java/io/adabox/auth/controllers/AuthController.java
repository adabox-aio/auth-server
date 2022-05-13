package io.adabox.auth.controllers;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.adabox.auth.components.CookieUtil;
import io.adabox.auth.config.ConfigProperties;
import io.adabox.auth.jwt.JwtService;
import io.adabox.auth.repositories.RoleRepository;
import io.adabox.auth.repositories.UserRepository;
import io.adabox.auth.repositories.models.ERole;
import io.adabox.auth.repositories.models.Role;
import io.adabox.auth.repositories.models.User;
import io.adabox.auth.services.TemporaryCodesService;
import io.adabox.auth.services.UserDetailsImpl;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URL;
import java.util.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final ConfigProperties configProperties;
    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JwtService jwtService;
    private final TemporaryCodesService temporaryCodesService;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final CookieUtil cookieUtil;

    @Autowired
    public AuthController(ConfigProperties configProperties, AuthenticationManager authenticationManager,
                          JwtService jwtService, TemporaryCodesService temporaryCodesService,
                          PasswordEncoder passwordEncoder, RoleRepository roleRepository, UserRepository userRepository,
                          CookieUtil cookieUtil) {
        this.configProperties = configProperties;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.temporaryCodesService = temporaryCodesService;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.cookieUtil = cookieUtil;
    }

    @ResponseBody
    @PostMapping("/hash")
    public ResponseEntity<String> getHash(@RequestParam("secret") String secret, @RequestParam("hash") String hash, @RequestParam("stakeAddress") String stakeAddress) {
        if (!passwordEncoder.matches(configProperties.getAppSecret(), secret)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String temporaryCode = UUID.randomUUID().toString();
        temporaryCodesService.put(temporaryCode, Pair.of(hash, stakeAddress));
        return ResponseEntity.ok(temporaryCode);
    }

    @ResponseBody
    @PostMapping("/authenticate")
    public ResponseEntity<User> authenticate(@RequestParam("secret") String secret, @RequestParam("code") String temporaryCode, @RequestParam("nonce") String nonce) {
        if (!passwordEncoder.matches(configProperties.getAppSecret(), secret)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        Pair<String, String> pair = temporaryCodesService.getIfPresent(temporaryCode);
        if (pair == null || StringUtils.isEmpty(pair.getFirst()) || StringUtils.isEmpty(pair.getSecond())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        try {
            String hash = pair.getFirst();
            String stakeAddress = pair.getSecond();
            if (passwordEncoder.matches(nonce, hash)) {
                Optional<User> optionalUser = userRepository.findByStakeKey(pair.getSecond());
                User user;
                Date date = new Date();
                if (optionalUser.isPresent()) {
                    user = optionalUser.get();
                } else {
                    Set<Role> roles = new HashSet<>();
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER).orElseThrow(() -> new IOException("Error: Role is not found."));
                    roles.add(userRole);
                    user = new User();
                    user.setRoles(roles);
                    user.setStakeKey(stakeAddress);
                    user.setImageUrl("https://avatars.dicebear.com/api/personas/" + stakeAddress + ".svg");
                    RandomUser randomUser = objectMapper.readValue(new URL("https://randomuser.me/api/?seed=" + stakeAddress + "&inc=login&noinfo"), RandomUser.class);
                    user.setUsername(randomUser.getUsername());
                    user.setPreferredLanguage("en");
                    user.setCreatedDate(date);
                }
                user.setNonce(hash);
                user.setModifiedDate(date);
                userRepository.save(user);
                Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(stakeAddress, nonce));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                String jwt = jwtService.generateJwtToken(authentication);
                UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
                temporaryCodesService.invalidate(temporaryCode);
                return ResponseEntity
                        .status(HttpStatus.OK)
                        .header(HttpHeaders.SET_COOKIE, cookieUtil.createAccessTokenCookie(jwt, configProperties.getJwtExpirationMs()/1000).toString())
                        .body(userDetails.getUser());
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class RandomUser {

        List<Result> results;

        public String getUsername() {
            if (results != null && !results.isEmpty() && results.get(0) != null && results.get(0).getLogin() != null) {
                return results.get(0).getLogin().getUsername();
            } else {
                return null;
            }
        }
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Result {
        private Login login;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Login {
        private String username;
    }
}
