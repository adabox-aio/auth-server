package io.adabox.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "cardano")
public class ConfigProperties {

    private String jwtSecretKey;
    private String jwtExpirationMs;
    private Network network;
    private String blockfrostApiKeyMainnet;
    private String blockfrostApiKeyTestnet;
    private String websiteUrl;
    private String explorerUrl;
    private String apiUrl;
}