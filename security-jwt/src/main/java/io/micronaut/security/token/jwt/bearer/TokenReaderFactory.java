package io.micronaut.security.token.jwt.bearer;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.bearer.BearerTokenConfigurationProperties;
import io.micronaut.security.token.bearer.BearerTokenReader;
import io.micronaut.security.token.jwt.cookie.JwtCookieTokenReader;

import javax.inject.Named;
import javax.inject.Singleton;

@Factory
@Requires(property = "micronaut.security.token.jwt.bearer.enabled", notEquals = StringUtils.FALSE)
public class TokenReaderFactory {

    @Named("jwt")
    @Singleton
    public BearerTokenReader tokenReader(JwtBearerTokenConfiguration jwtBearerTokenConfiguration) {
        return new BearerTokenReader(jwtBearerTokenConfiguration, JwtCookieTokenReader.ORDER - 100);
    }

    //todo use ForEachProperties and create named configuration for each token type
    @Named("jwt")
    @Singleton
    @ConfigurationProperties("micronaut.security.token.jwt.bearer")
    public static class JwtBearerTokenConfiguration extends BearerTokenConfigurationProperties {
    }
}
