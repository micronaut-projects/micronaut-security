package io.micronaut.security.token.jwt.signature.jwks.redis;

import io.micronaut.core.annotation.Nullable;

public interface RedisConfiguration {


    /**
     * Returns Redis host if enabled
     * @return The String used to set up Jedis Client
     */
    @Nullable
    String getRedisHost();

    /**
     * Returns the Redis port if enabled
     * @return The Integer port to set up Jedis Client
     */
    @Nullable
    Integer getRedisPort();

    @Nullable
    Boolean isEnabled();
}
