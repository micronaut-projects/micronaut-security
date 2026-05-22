package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultSecureEndpointConfigurationTest {

    @Test
    void defaultValueGetAuthenticationMethodIsClientSecretBasic() {
        DefaultSecureEndpointConfiguration endpoint = new DefaultSecureEndpointConfiguration();
        assertTrue(endpoint.getAuthenticationMethod().isPresent());
        assertEquals("client_secret_basic", endpoint.getAuthenticationMethod().get());
        endpoint.setAuthenticationMethod(AuthenticationMethods.CLIENT_SECRET_POST);
        assertEquals("client_secret_post", endpoint.getAuthenticationMethod().get());
    }
}
