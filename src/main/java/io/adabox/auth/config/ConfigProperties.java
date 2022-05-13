package io.adabox.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "config")
public class ConfigProperties {

    private List<String> firewallWhitelist;
    private String cypherKey;
    private String appSecret;
    private String jwtSecretKey;
    private Long jwtExpirationMs;
}