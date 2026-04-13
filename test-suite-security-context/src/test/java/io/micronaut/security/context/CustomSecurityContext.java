package io.micronaut.security.context;

import io.micronaut.security.authentication.Authentication;

/**
 * Test {@link SecurityContext} implementation used to verify supplier SPI loading.
 */
public class CustomSecurityContext implements SecurityContext {
    @Override
    public Authentication getAuthentication() {
        return null;
    }

    @Override
    public String getToken() {
        return "";
    }

    @Override
    public void setAuthentication(Authentication authentication) {

    }

    @Override
    public void setToken(String token) {

    }

    @Override
    public void setRejectionStatus(int statusCode) {

    }

    @Override
    public Integer getRejectionStatus() {
        return null;
    }

    @Override
    public void clear() {

    }
}
