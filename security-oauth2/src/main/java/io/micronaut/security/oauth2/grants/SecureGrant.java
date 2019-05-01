package io.micronaut.security.oauth2.grants;

public interface SecureGrant {

    void setClientId(String clientId);

    void setClientSecret(String clientSecret);
}
