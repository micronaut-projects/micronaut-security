package io.micronaut.security.oauth2.url;

import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;

import javax.inject.Singleton;

@Singleton
public class LogoutUrlBuilder extends AbstractUrlBuilder {

    LogoutUrlBuilder(HostResolver hostResolver,
                     OauthConfigurationProperties oauthConfigurationProperties) {
        super(hostResolver, oauthConfigurationProperties.getLogoutUri());
    }

}
