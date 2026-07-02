package io.micronaut.security.oauth2.client;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "micronaut.security.oauth2.clients.chesscom.openid.authorization.url", value = "https://oauth.chess.com/authorize")
@Property(name = "micronaut.security.oauth2.clients.chesscom.openid.token.url", value = "https://oauth.chess.com/token")
@Property(name = "micronaut.security.oauth2.clients.chesscom.openid.jwks-uri", value = "https://oauth.chess.com/certs")
@Property(name = "micronaut.security.oauth2.clients.chesscom.openid.issuer", value = "https://oauth.chess.com")
@Property(name = "micronaut.security.oauth2.clients.chesscom.openid.fetch-configuration", value = StringUtils.FALSE)
@MicronautTest(startApplication = false)
class OpenIdProviderMetadataFetcherFactoryDisableTest {

    @Inject
    BeanContext beanContext;

    @Test
    void youCanDisableABeanOfTypeOpenIdProviderMetadataFetcher() {
        assertTrue(beanContext.containsBean(OpenIdClientConfiguration.class, Qualifiers.byName("chesscom")));
        assertTrue(!beanContext.containsBean(OpenIdProviderMetadataFetcher.class, Qualifiers.byName("chesscom")));
        assertTrue(beanContext.containsBean(DefaultOpenIdProviderMetadata.class, Qualifiers.byName("chesscom")));
        DefaultOpenIdProviderMetadata metadata = beanContext.getBean(DefaultOpenIdProviderMetadata.class, Qualifiers.byName("chesscom"));
        assertEquals("https://oauth.chess.com/authorize", metadata.getAuthorizationEndpoint());
        assertEquals("https://oauth.chess.com/token", metadata.getTokenEndpoint());
        assertEquals("https://oauth.chess.com/certs", metadata.getJwksUri());
        assertEquals("https://oauth.chess.com", metadata.getIssuer());
    }

}
