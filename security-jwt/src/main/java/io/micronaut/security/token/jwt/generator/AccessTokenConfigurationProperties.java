package io.micronaut.security.token.jwt.generator;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.ArgumentUtils;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;

import java.util.Optional;

@ConfigurationProperties(AccessTokenConfigurationProperties.PREFIX)
public class AccessTokenConfigurationProperties implements AccessTokenConfiguration {

    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".generator.access-token";

    /**
     * The default expiration.
     */
    @SuppressWarnings("WeakerAccess")
    public static final Integer DEFAULT_EXPIRATION = 3600;

    private Integer expiration = DEFAULT_EXPIRATION;

    public Optional<Integer> getExpiration() {
        return Optional.of(expiration);
    }

    /**
     * Access token expiration. Default value ({@value #DEFAULT_EXPIRATION}).
     * @param expiration The expiration
     */
    public void setExpiration(Integer expiration) {
        ArgumentUtils.requireNonNull("expiration", expiration);
        this.expiration = expiration;
    }

}
