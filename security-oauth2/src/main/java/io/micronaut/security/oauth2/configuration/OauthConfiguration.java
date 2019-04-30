package io.micronaut.security.oauth2.configuration;

import io.micronaut.core.util.Toggleable;

import java.util.Optional;

public interface OauthConfiguration extends Toggleable {

    String getLoginUri();

    String getCallbackUri();

    Optional<OpenIdConfiguration> getOpenid();
}
