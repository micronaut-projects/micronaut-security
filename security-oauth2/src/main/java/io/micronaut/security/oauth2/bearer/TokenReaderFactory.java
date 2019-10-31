package io.micronaut.security.oauth2.bearer;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Context;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.bearer.BearerTokenConfigurationProperties;
import io.micronaut.security.token.bearer.BearerTokenReader;

import javax.inject.Named;
import javax.inject.Singleton;

import static io.micronaut.security.oauth2.bearer.ClientCredentialsTokenValidator.OAUTH_TOKEN_AUTHORIZATION_CONFIG;

@Factory
public class TokenReaderFactory {

    @Named("oauth2")
    @Singleton
    public BearerTokenReader tokenReader(Oauth2BearerTokenConfiguration oauth2BearerTokenConfiguration) {
        return new BearerTokenReader(oauth2BearerTokenConfiguration);
    }

    @Named("oauth2")
    @Singleton
    @ConfigurationProperties(OAUTH_TOKEN_AUTHORIZATION_CONFIG)
    public static class Oauth2BearerTokenConfiguration extends BearerTokenConfigurationProperties {
    }
}
