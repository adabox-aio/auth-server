package io.adabox.auth.controllers;

import com.bloxbean.cardano.client.address.Address;
import com.bloxbean.cardano.client.address.AddressService;
import com.bloxbean.cardano.client.address.util.AddressUtil;
import com.bloxbean.cardano.client.cip.cip30.CIP30DataSigner;
import com.bloxbean.cardano.client.cip.cip30.DataSignature;
import com.bloxbean.cardano.client.exception.AddressExcepion;
import com.bloxbean.cardano.client.util.HexUtil;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.adabox.auth.captcha.CaptchaServiceV3;
import io.adabox.auth.captcha.ICaptchaService;
import io.adabox.auth.captcha.error.ReCaptchaInvalidException;
import io.adabox.auth.controllers.models.JwtResponse;
import io.adabox.auth.jwt.JwtService;
import io.adabox.auth.repositories.RoleRepository;
import io.adabox.auth.repositories.UserRepository;
import io.adabox.auth.repositories.models.ERole;
import io.adabox.auth.repositories.models.Role;
import io.adabox.auth.repositories.models.User;
import io.adabox.auth.services.NonceService;
import io.adabox.auth.services.UserDetailsImpl;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JwtService jwtService;
    private final ICaptchaService captchaServiceV3;
    private final NonceService nonceService;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService, ICaptchaService captchaServiceV3, NonceService nonceService, PasswordEncoder passwordEncoder, RoleRepository roleRepository, UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.captchaServiceV3 = captchaServiceV3;
        this.nonceService = nonceService;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
    }

    @ResponseBody
    @PostMapping("/connect")
    public ResponseEntity<String> connect(@RequestParam("token") String captchaToken, @RequestParam("walletAddress") String walletAddress) {
        try {
            captchaServiceV3.processResponse(captchaToken, CaptchaServiceV3.CONNECT);
        } catch (ReCaptchaInvalidException e) {
            log.warn("Invalid Captcha: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        if (walletAddress == null || walletAddress.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        try {
            String walletAddressDecoded = AddressUtil.bytesToAddress(HexUtil.decodeHexString(walletAddress));
            Address stakeKeyAddress = AddressService.getInstance().getStakeAddress(new Address(walletAddressDecoded));
            String nonce = UUID.randomUUID().toString();
            nonceService.put(stakeKeyAddress.getAddress(), nonce);
            String message = "Welcome to adabox.io!\n\n" +
                    "Click to sign in and accept the Adabox Terms of Service: https://adabox.io/tos\n\n" +
                    "This request will not trigger a blockchain transaction or cost any fees.\n\n" +
                    "Your authentication status will reset after 24 hours.\n\n" +
                    "Stake address:\n" + stakeKeyAddress.getAddress() + "\n\n" +
                    "Nonce:\n" + nonce;
            return ResponseEntity.ok(HexUtil.encodeHexString(message.getBytes(StandardCharsets.UTF_8)));
        } catch (AddressExcepion e) {
            log.error("Bad Request, Cannot get stake key address out of wallet address: " + walletAddress);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @ResponseBody
    @PostMapping("/verifySignature")
    public ResponseEntity<JwtResponse> verifySignature(@RequestParam("token") String captchaToken, @RequestParam("walletAddress") String walletAddress, @RequestBody String jsonDataSignature) {
        try {
            captchaServiceV3.processResponse(captchaToken, "verifySignature");
        } catch (ReCaptchaInvalidException e) {
            log.warn("Invalid Captcha: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String walletAddressDecoded;
        try {
            walletAddressDecoded = AddressUtil.bytesToAddress(HexUtil.decodeHexString(walletAddress));
            Address stakeKeyAddress = AddressService.getInstance().getStakeAddress(new Address(walletAddressDecoded));
            DataSignature dataSignature = DataSignature.from(jsonDataSignature);
            dataSignature.signature(dataSignature.signature());
            dataSignature.key(dataSignature.key());
            String payload = new String(dataSignature.coseSign1().payload());
            String nonce = payload.substring(payload.lastIndexOf("\n")).replace("\n", "");
            boolean verified = CIP30DataSigner.INSTANCE.verify(dataSignature);
            String returnedNonce = nonceService.getIfPresent(stakeKeyAddress.getAddress());
            if (returnedNonce == null) {
                return ResponseEntity.status(HttpStatus.GONE).build();
            }
            if (verified && passwordEncoder.matches(nonce, returnedNonce)) {
                Optional<User> optionalUser = userRepository.findByStakeKey(stakeKeyAddress.getAddress());
                User user;
                Date date = new Date();
                boolean isNew = false;
                if (optionalUser.isPresent()) {
                    user = optionalUser.get();
                } else {
                    Set<Role> roles = new HashSet<>();
                    Role userRole = roleRepository.findByName(ERole.USER).orElseThrow(() -> new IOException("Error: Role is not found."));
                    roles.add(userRole);
                    user = new User();
                    user.setRoles(roles);
                    user.setStakeKey(stakeKeyAddress.getAddress());
                    user.setWalletAddress(walletAddressDecoded);
                    user.setImageURL("https://avatars.dicebear.com/api/personas/" + stakeKeyAddress.getAddress() + ".svg");
                    RandomUser randomUser = objectMapper.readValue(new URL("https://randomuser.me/api/?seed=" + stakeKeyAddress.getAddress() + "&inc=login&noinfo"), RandomUser.class);
                    user.setUsername(randomUser.getUsername());
                    user.setPreferredLanguage("en");
                    user.setCreatedDate(date);
                    isNew = true;
                }
                user.setModifiedDate(date);
                userRepository.save(user);
                Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(stakeKeyAddress.getAddress(), nonce));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                String jwt = jwtService.generateJwtToken(authentication);
                UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
                List<String> roles = userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList());
                return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getUser(), roles, isNew));
            } else {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
            }
        } catch (AddressExcepion | IOException e) {
            log.error(e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
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
