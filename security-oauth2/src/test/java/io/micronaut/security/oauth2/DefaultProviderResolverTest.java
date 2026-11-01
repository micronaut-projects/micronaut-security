package io.micronaut.security.oauth2;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.token.Claims;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Two Oracle Cloud identity domains share the same ID token {@code iss} claim ({@code https://identity.oraclecloud.com/}),
 * so the issuer alone cannot tell which OpenID client authenticated the user. The {@code aud} claim must be used to pick
 * the provider, and when the provider cannot be determined unambiguously no provider must be returned.
 */
@MicronautTest(startApplication = false)
@Property(name = "micronaut.security.enabled", value = StringUtils.TRUE)
@Property(name = "micronaut.security.authentication", value = "idtoken")
@Property(name = "micronaut.security.oauth2.clients.domainone.client-id", value = DefaultProviderResolverTest.DOMAIN_ONE_CLIENT_ID)
@Property(name = "micronaut.security.oauth2.clients.domainone.openid.issuer", value = "https://idcs-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.identity.oraclecloud.com")
@Property(name = "micronaut.security.oauth2.clients.domainone.openid.issuer-identifier", value = DefaultProviderResolverTest.ORACLE_CLOUD_ISS)
@Property(name = "micronaut.security.oauth2.clients.domaintwo.client-id", value = DefaultProviderResolverTest.DOMAIN_TWO_CLIENT_ID)
@Property(name = "micronaut.security.oauth2.clients.domaintwo.openid.issuer", value = "https://idcs-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.identity.oraclecloud.com")
@Property(name = "micronaut.security.oauth2.clients.domaintwo.openid.issuer-identifier", value = DefaultProviderResolverTest.ORACLE_CLOUD_ISS)
@Property(name = "micronaut.security.oauth2.clients.disabled.enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.oauth2.clients.disabled.client-id", value = DefaultProviderResolverTest.DOMAIN_ONE_CLIENT_ID)
@Property(name = "micronaut.security.oauth2.clients.disabled.openid.issuer", value = "https://idcs-cccccccccccccccccccccccccccccccc.identity.oraclecloud.com")
@Property(name = "micronaut.security.oauth2.clients.disabled.openid.issuer-identifier", value = DefaultProviderResolverTest.ORACLE_CLOUD_ISS)
@Property(name = "micronaut.security.oauth2.clients.cognito.client-id", value = DefaultProviderResolverTest.COGNITO_CLIENT_ID)
@Property(name = "micronaut.security.oauth2.clients.cognito.openid.issuer", value = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_test-fixture/")
class DefaultProviderResolverTest {

    static final String DOMAIN_ONE_CLIENT_ID = "domain-one-client-id-test-fixture-not-a-secret";
    static final String DOMAIN_TWO_CLIENT_ID = "domain-two-client-id-test-fixture-not-a-secret";
    static final String COGNITO_CLIENT_ID = "cognito-client-id-test-fixture-not-a-secret";
    static final String ORACLE_CLOUD_ISS = "https://identity.oraclecloud.com/";
    private static final String COGNITO_ISS = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_test-fixture";

    @Inject
    ProviderResolver providerResolver;

    @Inject
    List<OauthClientConfiguration> oauthClientConfigurations;

    @Test
    void providerAttributeTakesPrecedence() {
        // the attribute is set by the application (authorization code flow, UserInfo token validator); an ID token carrying a
        // claim with that name does not authenticate, see IdTokenClaimsValidatorReservedClaimsTest
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            OauthAuthenticationMapper.PROVIDER_KEY, "domaintwo",
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID))));
        assertEquals(Optional.of("domaintwo"), provider);

        provider = providerResolver.resolveProvider(authentication(Map.of(
            OauthAuthenticationMapper.PROVIDER_KEY, "domaintwo")));
        assertEquals(Optional.of("domaintwo"), provider);
    }

    @Test
    void singleIssuerMatchIsResolvedWithoutAudience() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, COGNITO_ISS)));
        assertEquals(Optional.of("cognito"), provider);
    }

    @Test
    void overlappingIssuersAreDisambiguatedByAudienceList() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_TWO_CLIENT_ID))));
        assertEquals(Optional.of("domaintwo"), provider);

        provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID))));
        assertEquals(Optional.of("domainone"), provider);
    }

    @Test
    void overlappingIssuersAreDisambiguatedByAudienceString() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, DOMAIN_TWO_CLIENT_ID)));
        assertEquals(Optional.of("domaintwo"), provider);
    }

    @Test
    void multipleAudiencesAreDisambiguatedByAuthorizedParty() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID, DOMAIN_TWO_CLIENT_ID),
            "azp", DOMAIN_TWO_CLIENT_ID)));
        assertEquals(Optional.of("domaintwo"), provider);
    }

    @Test
    void disabledClientDoesNotMakeResolutionAmbiguous() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID))));
        assertEquals(Optional.of("domainone"), provider);
    }

    @Test
    void authorizedPartyIsComparedCaseSensitively() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID, DOMAIN_TWO_CLIENT_ID),
            "azp", DOMAIN_TWO_CLIENT_ID.toUpperCase())));
        assertTrue(provider.isEmpty());
    }

    @Test
    void overlappingIssuersWithoutAudienceResolveNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS)));
        assertTrue(provider.isEmpty());
    }

    @Test
    void overlappingIssuersWithUnknownAudienceResolveNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of("unknown-client-id-test-fixture-not-a-secret"))));
        assertTrue(provider.isEmpty());
    }

    @Test
    void multipleAudiencesWithoutAuthorizedPartyResolveNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID, DOMAIN_TWO_CLIENT_ID))));
        assertTrue(provider.isEmpty());
    }

    @Test
    void audienceAloneDoesNotResolveProviderWhoseIssuerDoesNotMatch() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(COGNITO_CLIENT_ID))));
        assertTrue(provider.isEmpty());
    }

    @Test
    void unknownIssuerResolvesNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, "https://login.example.com",
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID))));
        assertTrue(provider.isEmpty());
    }

    @Test
    void missingIssuerResolvesNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(Map.of(
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID))));
        assertTrue(provider.isEmpty());
    }

    @Test
    void subclassVetoingTheIssuerIsAuthoritative() {
        DefaultProviderResolver resolver = new DefaultProviderResolver(openIdClientConfigurations(), oauthClientConfigurations) {
            @Override
            protected Optional<String> openIdClientNameWhichMatchesIssuer(String issuer) {
                return Optional.empty();
            }
        };
        assertTrue(resolver.resolveProvider(authentication(Map.of(Claims.ISSUER, COGNITO_ISS))).isEmpty());
        assertTrue(resolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, COGNITO_ISS,
            Claims.AUDIENCE, List.of(COGNITO_CLIENT_ID)))).isEmpty());
        // the veto holds for issuers shared by several clients: the aud claim is not consulted
        assertTrue(resolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID)))).isEmpty());
        assertTrue(resolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID, DOMAIN_TWO_CLIENT_ID),
            "azp", DOMAIN_TWO_CLIENT_ID))).isEmpty());
    }

    @Test
    void subclassMappingTheIssuerToAnotherClientIsHonored() {
        DefaultProviderResolver resolver = new DefaultProviderResolver(openIdClientConfigurations(), oauthClientConfigurations) {
            @Override
            protected Optional<String> openIdClientNameWhichMatchesIssuer(String issuer) {
                return Optional.of("custom");
            }
        };
        assertEquals(Optional.of("custom"), resolver.resolveProvider(authentication(Map.of(Claims.ISSUER, COGNITO_ISS))));
        assertEquals(Optional.of("custom"), resolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_ONE_CLIENT_ID)))));
    }

    @Test
    void subclassReturningOneOfSeveralClientsSharingTheIssuerDefersToTheAudience() {
        DefaultProviderResolver resolver = new DefaultProviderResolver(openIdClientConfigurations(), oauthClientConfigurations) {
            @Override
            protected Optional<String> openIdClientNameWhichMatchesIssuer(String issuer) {
                return Optional.of("domainone");
            }
        };
        assertEquals(Optional.of("domaintwo"), resolver.resolveProvider(authentication(Map.of(
            Claims.ISSUER, ORACLE_CLOUD_ISS,
            Claims.AUDIENCE, List.of(DOMAIN_TWO_CLIENT_ID)))));
        assertTrue(resolver.resolveProvider(authentication(Map.of(Claims.ISSUER, ORACLE_CLOUD_ISS))).isEmpty());
        // for an issuer matching a single client the hook's answer is used as is
        assertEquals(Optional.of("domainone"), resolver.resolveProvider(authentication(Map.of(Claims.ISSUER, COGNITO_ISS))));
    }

    private List<OpenIdClientConfiguration> openIdClientConfigurations() {
        return oauthClientConfigurations.stream()
            .map(OauthClientConfiguration::getOpenid)
            .flatMap(Optional::stream)
            .toList();
    }

    private static Authentication authentication(Map<String, Object> attributes) {
        return Authentication.build("user", attributes);
    }
}
