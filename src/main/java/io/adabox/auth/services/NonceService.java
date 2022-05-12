package io.adabox.auth.services;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class NonceService {

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private final LoadingCache<String, String> nonceCache = CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.DAYS).build(
            new CacheLoader<>() {
                @Override
                public @NotNull String load(@NotNull String key) {
                    return key;
                }
            }
    );

    public void put(String stakeKey, String nonce) {
        nonceCache.put(stakeKey, passwordEncoder.encode(nonce));
    }

    public String getIfPresent(String stakeKey) {
        return nonceCache.getIfPresent(stakeKey);
    }

    public void invalidate(String stakeKey) {
        nonceCache.invalidate(stakeKey);
    }
}
