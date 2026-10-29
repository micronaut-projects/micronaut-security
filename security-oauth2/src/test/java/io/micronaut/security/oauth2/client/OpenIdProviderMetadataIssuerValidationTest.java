package io.micronaut.security.oauth2.client;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.validation.IssuerClaimValidator;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * OpenID Connect Discovery 1.0, section 4.3: the {@code issuer} returned in the discovery document MUST be identical
 * to the issuer used to retrieve it. A provider announcing another provider's issuer must not get that issuer accepted.
 */
class OpenIdProviderMetadataIssuerValidationTest {
    private static final String SPEC_NAME = "OpenIdProviderMetadataIssuerValidationTest";
    private static final String PROVIDER_SPEC_NAME = SPEC_NAME + ".provider";
    private static final String ISSUER_PATH = "/oauth2/default";
    private static final String ALPHA = "alpha";
    private static final String BETA = "beta";
    private static final String GAMMA = "gamma";
    private static final String PUBLIC_ISSUER = "https://sso.example.com/oauth2/default";

    private static EmbeddedServer alphaProvider;
    private static EmbeddedServer betaProvider;
    private static EmbeddedServer internalProvider;
    private static ApplicationContext relyingParty;

    @BeforeAll
    static void start() {
        betaProvider = ApplicationContext.run(EmbeddedServer.class, Collections.singletonMap("spec.name", PROVIDER_SPEC_NAME));
        // alpha is a malicious provider: its discovery document announces beta's issuer
        alphaProvider = ApplicationContext.run(EmbeddedServer.class, provider(issuer(betaProvider)));
        // discovery over an internal URL, tokens carry the public issuer
        internalProvider = ApplicationContext.run(EmbeddedServer.class, provider(PUBLIC_ISSUER));
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.security.oauth2.clients." + ALPHA + ".openid.issuer", issuer(alphaProvider));
        configuration.put("micronaut.security.oauth2.clients." + BETA + ".openid.issuer", issuer(betaProvider));
        configuration.put("micronaut.security.oauth2.clients." + GAMMA + ".openid.issuer", issuer(internalProvider));
        configuration.put("micronaut.security.oauth2.clients." + GAMMA + ".openid.issuer-identifier", PUBLIC_ISSUER);
        for (String provider : Arrays.asList(ALPHA, BETA, GAMMA)) {
            configuration.put("micronaut.security.oauth2.clients." + provider + ".client-id", provider + "-client");
            configuration.put("micronaut.security.oauth2.clients." + provider + ".client-secret", "test-fixture-not-a-secret");
        }
        relyingParty = ApplicationContext.run(configuration);
    }

    @AfterAll
    static void stop() {
        relyingParty.close();
        alphaProvider.close();
        betaProvider.close();
        internalProvider.close();
    }

    @Test
    void discoveredIssuerMatchingTheConfiguredIssuerIsKept() {
        assertEquals(issuer(betaProvider), metadata(BETA).getIssuer());
        assertEquals(issuer(betaProvider) + "/keys", metadata(BETA).getJwksUri());
    }

    @Test
    void discoveredIssuerNotMatchingTheConfiguredIssuerIsReplacedByTheConfiguredIssuer() {
        assertEquals(issuer(alphaProvider), metadata(ALPHA).getIssuer());
        // the rest of the discovery document is still used
        assertEquals(issuer(betaProvider) + "/keys", metadata(ALPHA).getJwksUri());
    }

    @Test
    void providerCannotGetAnotherProviderIssuerAcceptedViaItsDiscoveryDocument() {
        IssuerClaimValidator validator = relyingParty.getBean(IssuerClaimValidator.class);
        assertFalse(validator.validate(claims(issuer(betaProvider)), client(ALPHA), metadata(ALPHA)));
        assertTrue(validator.validate(claims(issuer(alphaProvider)), client(ALPHA), metadata(ALPHA)));
        assertTrue(validator.validate(claims(issuer(betaProvider)), client(BETA), metadata(BETA)));
        assertFalse(validator.validate(claims(issuer(alphaProvider)), client(BETA), metadata(BETA)));
    }

    @Test
    void issuerIdentifierAllowsDiscoveryOverAnInternalUrlWithAPublicIssuerInTokens() {
        assertEquals(PUBLIC_ISSUER, metadata(GAMMA).getIssuer());
        IssuerClaimValidator validator = relyingParty.getBean(IssuerClaimValidator.class);
        assertTrue(validator.validate(claims(PUBLIC_ISSUER), client(GAMMA), metadata(GAMMA)));
        assertFalse(validator.validate(claims(issuer(internalProvider)), client(GAMMA), metadata(GAMMA)));
        assertFalse(validator.validate(claims(issuer(betaProvider)), client(GAMMA), metadata(GAMMA)));
    }

    private static Map<String, Object> provider(String announcedIssuer) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", PROVIDER_SPEC_NAME);
        properties.put("mock.provider.announced-issuer", announcedIssuer);
        return properties;
    }

    private static String issuer(EmbeddedServer provider) {
        return provider.getURL() + ISSUER_PATH;
    }

    private static OauthClientConfiguration client(String name) {
        return relyingParty.getBean(OauthClientConfiguration.class, Qualifiers.byName(name));
    }

    private static DefaultOpenIdProviderMetadata metadata(String name) {
        return relyingParty.getBean(DefaultOpenIdProviderMetadata.class, Qualifiers.byName(name));
    }

    private static OpenIdClaims claims(String issuer) {
        return new JWTOpenIdClaims(new JWTClaimsSet.Builder().issuer(issuer).build());
    }

    @Requires(property = "spec.name", value = PROVIDER_SPEC_NAME)
    @Secured(SecurityRule.IS_ANONYMOUS)
    @Controller(ISSUER_PATH)
    static class ProviderController {
        private final HttpHostResolver httpHostResolver;
        private final String announcedIssuer;

        ProviderController(HttpHostResolver httpHostResolver,
                           @Property(name = "mock.provider.announced-issuer") @Nullable String announcedIssuer) {
            this.httpHostResolver = httpHostResolver;
            this.announcedIssuer = announcedIssuer;
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/.well-known/openid-configuration")
        String configuration(HttpRequest<?> request) {
            String issuer = announcedIssuer != null ? announcedIssuer : httpHostResolver.resolve(request) + ISSUER_PATH;
            return "{\"issuer\":\"" + issuer + "\","
                + "\"authorization_endpoint\":\"" + issuer + "/v1/authorize\","
                + "\"token_endpoint\":\"" + issuer + "/v1/token\","
                + "\"jwks_uri\":\"" + issuer + "/keys\","
                + "\"response_types_supported\":[\"code\"],"
                + "\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
        }
    }
}
