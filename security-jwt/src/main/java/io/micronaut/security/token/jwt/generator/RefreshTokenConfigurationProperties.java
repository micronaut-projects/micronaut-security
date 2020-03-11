package io.micronaut.security.token.jwt.generator;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;

import java.util.Optional;

@ConfigurationProperties(RefreshTokenConfigurationProperties.PREFIX)
public class RefreshTokenConfigurationProperties implements RefreshTokenConfiguration {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".generator.refresh-token";

    private Integer expiration;
    private boolean enabled = false;
    private String secret;

    public Optional<Integer> getExpiration() {
        return Optional.ofNullable(expiration);
    }

    public void setExpiration(Integer expiration) {
        this.expiration = expiration;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public Optional<String> getSecret() {
        return Optional.ofNullable(secret);
    }

    public void setSecret(String secret) {
        ArgumentUtils.requireNonNull("secret", secret);
        this.secret = secret;
    }
}
