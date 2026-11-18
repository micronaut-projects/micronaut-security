package io.micronaut.security.oauth2.client;

import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The JWKS signature configuration of an OpenID provider must not fail while the provider metadata is unavailable, and
 * must pick the metadata up once it can be resolved.
 */
class OpenIdProviderMetadataJwksSignatureConfigurationTest {
    private static final String CONFIGURED_ISSUER = "https://idp.example.com/oauth2/default";

    @Test
    void noUrlWhileTheMetadataIsUnavailableAndTheMetadataIsUsedOnceItResolves() throws MalformedURLException {
        OpenIdClientConfiguration clientConfiguration = mock(OpenIdClientConfiguration.class);
        when(clientConfiguration.getIssuer()).thenReturn(Optional.of(new URL(CONFIGURED_ISSUER)));
        AtomicBoolean available = new AtomicBoolean();
        JwksSignatureConfiguration configuration = new JwksUriSignatureFactory.OpenIdProviderMetadataJwksSignatureConfiguration("okta", clientConfiguration, () -> {
            if (!available.get()) {
                throw new IllegalStateException("metadata unavailable");
            }
            return metadata(CONFIGURED_ISSUER + "/");
        });

        assertEquals("okta", configuration.getName());
        assertNull(configuration.getUrl());
        assertEquals(CONFIGURED_ISSUER, configuration.getIssuer());

        available.set(true);

        assertEquals(CONFIGURED_ISSUER + "/v1/keys", configuration.getUrl());
        assertEquals(CONFIGURED_ISSUER + "/", configuration.getIssuer());
        assertNull(configuration.getKeyType());
    }

    @Test
    void issuerIsNullWhenNeitherTheMetadataNorTheClientDeclareOne() {
        JwksSignatureConfiguration configuration = new JwksUriSignatureFactory.OpenIdProviderMetadataJwksSignatureConfiguration("okta", null,
            () -> metadata(null));

        assertNull(configuration.getIssuer());
        assertEquals(CONFIGURED_ISSUER + "/v1/keys", configuration.getUrl());
    }

    private static DefaultOpenIdProviderMetadata metadata(String issuer) {
        DefaultOpenIdProviderMetadata metadata = new DefaultOpenIdProviderMetadata("okta");
        metadata.setJwksUri(CONFIGURED_ISSUER + "/v1/keys");
        if (issuer != null) {
            metadata.setIssuer(issuer);
        }
        return metadata;
    }
}
