package io.micronaut.security.token.jwt.signature.jwks.redis;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.config.TokenConfigurationProperties;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;

@Requires(property = TokenConfigurationProperties.PREFIX + ".signatures.jwks.redis.enabled", notEquals = StringUtils.FALSE)
@ConfigurationProperties(JwtConfigurationProperties.PREFIX + ".signatures.jwks.redis")
public class RedisConfigurationProperties implements RedisConfiguration {


    public static final String PREFIX = JwtConfigurationProperties.PREFIX + ".signatures.jwks.redis";

    private String host;
    private Integer port;

    private Boolean isEnabled = false;

    @Override
    public String getRedisHost() {
        return host;
    }

    public void setRedisHost(String host) {
        this.host = host;
    }

    @Override
    public Integer getRedisPort() {
        return port;
    }

    @Override
    public Boolean isEnabled() {
        return isEnabled;
    }

    public void setIsEnabled(Boolean isEnabled) {
        this.isEnabled = isEnabled;
    }

    public void setRedisPort(Integer port) {
        this.port = port;
    }
}
