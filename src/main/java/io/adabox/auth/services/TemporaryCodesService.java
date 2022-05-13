package io.adabox.auth.services;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.jetbrains.annotations.NotNull;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TemporaryCodesService {

    private final LoadingCache<String, Pair<String,String>> temporaryCodesCache = CacheBuilder.newBuilder().expireAfterWrite(1, TimeUnit.DAYS).build(
            new CacheLoader<>() {
                @Override
                public @NotNull Pair<String,String> load(@NotNull String key) {
                    return Pair.of(key,key);
                }
            }
    );

    public void put(String temporaryCode, Pair<String,String> pair) {
        temporaryCodesCache.put(temporaryCode, pair);
    }

    public Pair<String,String> getIfPresent(String temporaryCode) {
        return temporaryCodesCache.getIfPresent(temporaryCode);
    }

    public void invalidate(String temporaryCode) {
        temporaryCodesCache.invalidate(temporaryCode);
    }
}
