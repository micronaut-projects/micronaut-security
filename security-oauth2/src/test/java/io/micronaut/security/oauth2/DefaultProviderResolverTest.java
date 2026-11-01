/*
 * Copyright 2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2;

import io.micronaut.context.ApplicationContext;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Two Oracle Cloud identity domains share the same ID token {@code iss} claim ({@code https://identity.oraclecloud.com/}),
 * so the issuer alone cannot tell which OpenID client authenticated the user. The {@code aud} claim must be used to pick
 * the provider, and when the provider cannot be determined unambiguously no provider must be returned.
 */
class DefaultProviderResolverTest {

    static final String DOMAIN_ONE_CLIENT_ID = "domain-one-client-id-test-fixture-not-a-secret";
    static final String DOMAIN_TWO_CLIENT_ID = "domain-two-client-id-test-fixture-not-a-secret";
    static final String COGNITO_CLIENT_ID = "cognito-client-id-test-fixture-not-a-secret";
    static final String ORACLE_CLOUD_ISS = "https://identity.oraclecloud.com/";
    private static final String COGNITO_ISS = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_test-fixture";

    private static ApplicationContext context;
    private static ProviderResolver providerResolver;
    private static List<OauthClientConfiguration> oauthClientConfigurations;

    @BeforeAll
    static void startContext() {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("micronaut.security.enabled", StringUtils.TRUE);
        configuration.put("micronaut.security.authentication", "idtoken");
        // on this branch discovery is fetched at startup: point it at a closed port so it fails fast, and put the
        // issuer under test in issuer-identifier, which is the value the resolver compares the iss claim with
        configuration.put("micronaut.security.oauth2.clients.domainone.client-id", DOMAIN_ONE_CLIENT_ID);
        configuration.put("micronaut.security.oauth2.clients.domainone.client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.domainone.openid.issuer", "http://localhost:1/idcs-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        configuration.put("micronaut.security.oauth2.clients.domainone.openid.issuer-identifier", ORACLE_CLOUD_ISS);
        configuration.put("micronaut.security.oauth2.clients.domaintwo.client-id", DOMAIN_TWO_CLIENT_ID);
        configuration.put("micronaut.security.oauth2.clients.domaintwo.client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.domaintwo.openid.issuer", "http://localhost:1/idcs-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        configuration.put("micronaut.security.oauth2.clients.domaintwo.openid.issuer-identifier", ORACLE_CLOUD_ISS);
        configuration.put("micronaut.security.oauth2.clients.disabled.enabled", StringUtils.FALSE);
        configuration.put("micronaut.security.oauth2.clients.disabled.client-id", DOMAIN_ONE_CLIENT_ID);
        configuration.put("micronaut.security.oauth2.clients.disabled.client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.disabled.openid.issuer", "http://localhost:1/idcs-cccccccccccccccccccccccccccccccc");
        configuration.put("micronaut.security.oauth2.clients.disabled.openid.issuer-identifier", ORACLE_CLOUD_ISS);
        configuration.put("micronaut.security.oauth2.clients.cognito.client-id", COGNITO_CLIENT_ID);
        configuration.put("micronaut.security.oauth2.clients.cognito.client-secret", "test-fixture-not-a-secret");
        configuration.put("micronaut.security.oauth2.clients.cognito.openid.issuer", "http://localhost:1/cognito");
        configuration.put("micronaut.security.oauth2.clients.cognito.openid.issuer-identifier", COGNITO_ISS + "/");
        context = ApplicationContext.run(configuration);
        providerResolver = context.getBean(ProviderResolver.class);
        oauthClientConfigurations = new ArrayList<>(context.getBeansOfType(OauthClientConfiguration.class));
    }

    @AfterAll
    static void stopContext() {
        context.close();
    }

    @Test
    void providerAttributeTakesPrecedence() {
        // the attribute is set by the application (authorization code flow); an ID token carrying a
        // claim with that name does not authenticate, see IdTokenClaimsValidatorReservedClaimsTest
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            OauthAuthenticationMapper.PROVIDER_KEY, "domaintwo",
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID)));
        assertEquals(Optional.of("domaintwo"), provider);

        provider = providerResolver.resolveProvider(authentication(
            OauthAuthenticationMapper.PROVIDER_KEY, "domaintwo"));
        assertEquals(Optional.of("domaintwo"), provider);
    }

    @Test
    void singleIssuerMatchIsResolvedWithoutAudience() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, COGNITO_ISS));
        assertEquals(Optional.of("cognito"), provider);
    }

    @Test
    void overlappingIssuersAreDisambiguatedByAudienceList() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_TWO_CLIENT_ID)));
        assertEquals(Optional.of("domaintwo"), provider);

        provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID)));
        assertEquals(Optional.of("domainone"), provider);
    }

    @Test
    void overlappingIssuersAreDisambiguatedByAudienceString() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, DOMAIN_TWO_CLIENT_ID));
        assertEquals(Optional.of("domaintwo"), provider);
    }

    @Test
    void multipleAudiencesAreDisambiguatedByAuthorizedParty() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID, DOMAIN_TWO_CLIENT_ID),
            "azp", DOMAIN_TWO_CLIENT_ID));
        assertEquals(Optional.of("domaintwo"), provider);
    }

    @Test
    void disabledClientDoesNotMakeResolutionAmbiguous() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID)));
        assertEquals(Optional.of("domainone"), provider);
    }

    @Test
    void authorizedPartyIsComparedCaseSensitively() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID, DOMAIN_TWO_CLIENT_ID),
            "azp", DOMAIN_TWO_CLIENT_ID.toUpperCase()));
        assertFalse(provider.isPresent());
    }

    @Test
    void overlappingIssuersWithoutAudienceResolveNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS));
        assertFalse(provider.isPresent());
    }

    @Test
    void overlappingIssuersWithUnknownAudienceResolveNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList("unknown-client-id-test-fixture-not-a-secret")));
        assertFalse(provider.isPresent());
    }

    @Test
    void multipleAudiencesWithoutAuthorizedPartyResolveNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID, DOMAIN_TWO_CLIENT_ID)));
        assertFalse(provider.isPresent());
    }

    @Test
    void audienceAloneDoesNotResolveProviderWhoseIssuerDoesNotMatch() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(COGNITO_CLIENT_ID)));
        assertFalse(provider.isPresent());
    }

    @Test
    void unknownIssuerResolvesNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.ISSUER, "https://login.example.com",
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID)));
        assertFalse(provider.isPresent());
    }

    @Test
    void missingIssuerResolvesNothing() {
        Optional<String> provider = providerResolver.resolveProvider(authentication(
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID)));
        assertFalse(provider.isPresent());
    }

    @Test
    void subclassVetoingTheIssuerIsAuthoritative() {
        DefaultProviderResolver resolver = new DefaultProviderResolver(openIdClientConfigurations(), oauthClientConfigurations) {
            @Override
            protected Optional<String> openIdClientNameWhichMatchesIssuer(String issuer) {
                return Optional.empty();
            }
        };
        assertFalse(resolver.resolveProvider(authentication(JwtClaims.ISSUER, COGNITO_ISS)).isPresent());
        assertFalse(resolver.resolveProvider(authentication(
            JwtClaims.ISSUER, COGNITO_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(COGNITO_CLIENT_ID))).isPresent());
        // the veto holds for issuers shared by several clients: the aud claim is not consulted
        assertFalse(resolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID))).isPresent());
        assertFalse(resolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID, DOMAIN_TWO_CLIENT_ID),
            "azp", DOMAIN_TWO_CLIENT_ID)).isPresent());
    }

    @Test
    void subclassMappingTheIssuerToAnotherClientIsHonored() {
        DefaultProviderResolver resolver = new DefaultProviderResolver(openIdClientConfigurations(), oauthClientConfigurations) {
            @Override
            protected Optional<String> openIdClientNameWhichMatchesIssuer(String issuer) {
                return Optional.of("custom");
            }
        };
        assertEquals(Optional.of("custom"), resolver.resolveProvider(authentication(JwtClaims.ISSUER, COGNITO_ISS)));
        assertEquals(Optional.of("custom"), resolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_ONE_CLIENT_ID))));
    }

    @Test
    void subclassReturningOneOfSeveralClientsSharingTheIssuerDefersToTheAudience() {
        DefaultProviderResolver resolver = new DefaultProviderResolver(openIdClientConfigurations(), oauthClientConfigurations) {
            @Override
            protected Optional<String> openIdClientNameWhichMatchesIssuer(String issuer) {
                return Optional.of("domainone");
            }
        };
        assertEquals(Optional.of("domaintwo"), resolver.resolveProvider(authentication(
            JwtClaims.ISSUER, ORACLE_CLOUD_ISS,
            JwtClaims.AUDIENCE, Arrays.asList(DOMAIN_TWO_CLIENT_ID))));
        assertFalse(resolver.resolveProvider(authentication(JwtClaims.ISSUER, ORACLE_CLOUD_ISS)).isPresent());
        // for an issuer matching a single client the hook's answer is used as is
        assertEquals(Optional.of("domainone"), resolver.resolveProvider(authentication(JwtClaims.ISSUER, COGNITO_ISS)));
    }

    private static List<OpenIdClientConfiguration> openIdClientConfigurations() {
        return oauthClientConfigurations.stream()
            .map(OauthClientConfiguration::getOpenid)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .collect(Collectors.toList());
    }

    private static Authentication authentication(Object... keysAndValues) {
        Map<String, Object> attributes = new HashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            attributes.put((String) keysAndValues[i], keysAndValues[i + 1]);
        }
        return Authentication.build("user", attributes);
    }
}
