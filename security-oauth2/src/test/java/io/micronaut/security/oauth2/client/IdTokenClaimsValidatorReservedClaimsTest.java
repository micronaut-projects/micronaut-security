package io.micronaut.security.oauth2.client;

import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.token.MapClaims;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * With {@code micronaut.security.authentication=idtoken} the attributes of the authentication are the claims of the ID token,
 * and {@code /oauth/logout} trusts the {@code oauth2Provider} attribute, which only the application sets, to pick the provider.
 * An ID token carrying a claim with a reserved attribute name must therefore not authenticate.
 */
class IdTokenClaimsValidatorReservedClaimsTest {
    private static final String ISSUER = "https://issuer.example.com";
    private static final String CLIENT_ID = "client-id-test-fixture-not-a-secret";

    @Test
    void tokenWithoutReservedClaimsIsAccepted() throws MalformedURLException {
        assertTrue(validator().validate(new MapClaims(claims()), null));
    }

    @Test
    void tokenCarryingTheProviderAttributeNameIsRejected() throws MalformedURLException {
        Map<String, Object> claims = claims();
        claims.put(OauthAuthenticationMapper.PROVIDER_KEY, "other");
        assertFalse(validator().validate(new MapClaims(claims), null));

        claims.put(OauthAuthenticationMapper.PROVIDER_KEY, "self");
        assertFalse(validator().validate(new MapClaims(claims), null), "the reserved name is rejected whatever its value");
    }

    @Test
    void tokenCarryingTheOpenIdTokenAttributeNameIsRejected() throws MalformedURLException {
        Map<String, Object> claims = claims();
        claims.put(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY, "any-value");
        assertFalse(validator().validate(new MapClaims(claims), null));
    }

    private static Map<String, Object> claims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", ISSUER);
        claims.put("aud", CLIENT_ID);
        claims.put("sub", "sherlock");
        return claims;
    }

    private static IdTokenClaimsValidator<Object> validator() throws MalformedURLException {
        OpenIdClientConfiguration openid = mock(OpenIdClientConfiguration.class);
        when(openid.getName()).thenReturn("self");
        when(openid.getIssuer()).thenReturn(Optional.of(new URL(ISSUER)));
        when(openid.getIssuerIdentifier()).thenReturn(Optional.of(ISSUER));
        // 4.x has no OauthClientConfiguration builder; mock the interface like the OpenID configuration above
        OauthClientConfiguration configuration = mock(OauthClientConfiguration.class);
        when(configuration.getName()).thenReturn("self");
        when(configuration.getClientId()).thenReturn(CLIENT_ID);
        when(configuration.getClientSecret()).thenReturn("test-fixture-not-a-secret");
        when(configuration.isEnabled()).thenReturn(true);
        when(configuration.getOpenid()).thenReturn(Optional.of(openid));
        return new IdTokenClaimsValidator<>(List.of(configuration));
    }
}
