package io.micronaut.security.oauth2.configuration;

import io.micronaut.core.util.Toggleable;

import java.util.Optional;

/**
 * OAuth 2.0 Configuration
 * @author James Kleeh
 * @since 1.0.0
 */
public interface OauthConfiguration extends Toggleable {

    /**
     *
     * @return the login Uri
     */
    String getLoginUri();

    /**
     *
     * @return the Callback Uri
     */
    String getCallbackUri();

    /**
     *
     * @return OpenID Connect Configuration
     */
    Optional<OpenIdConfiguration> getOpenid();
}
