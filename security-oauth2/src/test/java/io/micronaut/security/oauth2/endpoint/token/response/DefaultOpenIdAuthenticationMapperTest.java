package io.micronaut.security.oauth2.endpoint.token.response;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.config.AuthenticationModeConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdAdditionalClaimsConfiguration;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@code sub} claim is only unique within one OpenID provider. When several providers are configured the default
 * mapper must not map the same {@code sub} issued by two providers to the same user name.
 */
class DefaultOpenIdAuthenticationMapperTest {

    private static final String SUBJECT = "alice";
    private static final String PROVIDER_A = "provider-a";
    private static final String PROVIDER_B = "provider-b";

    @Test
    void sameSubjectAtTwoProvidersMapsToTwoDifferentUsers() {
        try (ApplicationContext context = ApplicationContext.run(config(PROVIDER_A, PROVIDER_B))) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);

            String userAtA = username(mapper, PROVIDER_A);
            String userAtB = username(mapper, PROVIDER_B);

            assertNotEquals(userAtA, userAtB, "same sub at two providers must not be the same user");
            assertEquals(PROVIDER_A + ":" + SUBJECT, userAtA);
            assertEquals(PROVIDER_B + ":" + SUBJECT, userAtB);
        }
    }

    @Test
    void providerNameIsStillAvailableAsAttributeWhenUsernameIsQualified() {
        try (ApplicationContext context = ApplicationContext.run(config(PROVIDER_A, PROVIDER_B))) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            AuthenticationResponse response = mapper.createAuthenticationResponse(PROVIDER_A, tokenResponse(), claims(), null);
            assertTrue(response.isAuthenticated());
            assertEquals(PROVIDER_A, response.getAuthentication().get().getAttributes().get(OauthAuthenticationMapper.PROVIDER_KEY));
        }
    }

    @Test
    void singleProviderKeepsSubjectAsUsername() {
        try (ApplicationContext context = ApplicationContext.run(config(PROVIDER_A))) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            assertFalse(mapper.isQualifyUsernameWithProvider());
            assertEquals(SUBJECT, username(mapper, PROVIDER_A));
        }
    }

    @Test
    void plainOauthClientCountsAsASecondClient() {
        // Same single-vs-multi-client rule as the UserInfo token validator: every enabled authenticating client counts.
        Map<String, Object> config = config(PROVIDER_A);
        config.put("micronaut.security.oauth2.clients.plain-oauth.client-id", "plain-oauth-client-id");
        config.put("micronaut.security.oauth2.clients.plain-oauth.client-secret", "test-fixture-not-a-secret");
        config.put("micronaut.security.oauth2.clients.plain-oauth.authorization.url", "https://plain.example.com/authorize");
        config.put("micronaut.security.oauth2.clients.plain-oauth.token.url", "https://plain.example.com/token");
        try (ApplicationContext context = ApplicationContext.run(config)) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            assertTrue(mapper.isQualifyUsernameWithProvider());
            assertEquals(PROVIDER_A + ":" + SUBJECT, username(mapper, PROVIDER_A));
        }
    }

    @Test
    void disabledClientDoesNotCount() {
        Map<String, Object> config = config(PROVIDER_A, PROVIDER_B);
        config.put("micronaut.security.oauth2.clients." + PROVIDER_B + ".enabled", StringUtils.FALSE);
        try (ApplicationContext context = ApplicationContext.run(config)) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            assertFalse(mapper.isQualifyUsernameWithProvider());
            assertEquals(SUBJECT, username(mapper, PROVIDER_A));
        }
    }

    @Test
    void clientCredentialsOnlyClientDoesNotCount() {
        Map<String, Object> config = config(PROVIDER_A);
        config.put("micronaut.security.oauth2.clients.machine.client-id", "machine-client-id");
        config.put("micronaut.security.oauth2.clients.machine.client-secret", "test-fixture-not-a-secret");
        config.put("micronaut.security.oauth2.clients.machine.grant-type", "client_credentials");
        config.put("micronaut.security.oauth2.clients.machine.token.url", "https://machine.example.com/token");
        try (ApplicationContext context = ApplicationContext.run(config)) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            assertFalse(mapper.isQualifyUsernameWithProvider());
            assertEquals(SUBJECT, username(mapper, PROVIDER_A));
        }
    }

    @Test
    void unqualifiedSubjectIsKeptAsAttributeOnlyWhenQualifying() {
        try (ApplicationContext context = ApplicationContext.run(config(PROVIDER_A, PROVIDER_B))) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            AuthenticationResponse response = mapper.createAuthenticationResponse(PROVIDER_A, tokenResponse(), claims(), null);
            assertEquals(SUBJECT, response.getAuthentication().get().getAttributes().get("sub"));
        }
        try (ApplicationContext context = ApplicationContext.run(config(PROVIDER_A))) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            AuthenticationResponse response = mapper.createAuthenticationResponse(PROVIDER_A, tokenResponse(), claims(), null);
            assertFalse(response.getAuthentication().get().getAttributes().containsKey("sub"));
        }
    }

    @Test
    void qualificationCanBeForcedForASingleProvider() {
        Map<String, Object> config = config(PROVIDER_A);
        config.put("micronaut.security.oauth2.openid.qualify-username-with-provider", StringUtils.TRUE);
        try (ApplicationContext context = ApplicationContext.run(config)) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            assertEquals(PROVIDER_A + ":" + SUBJECT, username(mapper, PROVIDER_A));
        }
    }

    @Test
    void qualificationCanBeDisabledForSeveralProviders() {
        Map<String, Object> config = config(PROVIDER_A, PROVIDER_B);
        config.put("micronaut.security.oauth2.openid.qualify-username-with-provider", StringUtils.FALSE);
        try (ApplicationContext context = ApplicationContext.run(config)) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            assertEquals(SUBJECT, username(mapper, PROVIDER_A));
            assertEquals(SUBJECT, username(mapper, PROVIDER_B));
        }
    }

    @Test
    void missingSubjectIsNotQualified() {
        try (ApplicationContext context = ApplicationContext.run(config(PROVIDER_A, PROVIDER_B))) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            OpenIdClaims claims = new JWTOpenIdClaims(new JWTClaimsSet.Builder().issuer("https://" + PROVIDER_A + ".example.com").build());
            assertNull(mapper.getUsername(PROVIDER_A, tokenResponse(), claims));
        }
    }

    @Test
    void deprecatedConstructorKeepsSubjectAsUsername() {
        OpenIdAdditionalClaimsConfiguration additionalClaims = new OpenIdAdditionalClaimsConfiguration() {
            @Override
            public boolean isJwt() {
                return false;
            }

            @Override
            public boolean isAccessToken() {
                return false;
            }

            @Override
            public boolean isRefreshToken() {
                return false;
            }
        };
        AuthenticationModeConfiguration authenticationMode = () -> null;
        @SuppressWarnings("deprecation")
        DefaultOpenIdAuthenticationMapper mapper = new DefaultOpenIdAuthenticationMapper(additionalClaims, authenticationMode);
        assertEquals(SUBJECT, username(mapper, PROVIDER_A));
        assertFalse(mapper.isQualifyUsernameWithProvider());
    }

    private static String username(DefaultOpenIdAuthenticationMapper mapper, String providerName) {
        AuthenticationResponse response = mapper.createAuthenticationResponse(providerName, tokenResponse(), claims(), null);
        assertTrue(response.isAuthenticated());
        return response.getAuthentication().get().getName();
    }

    private static OpenIdClaims claims() {
        return new JWTOpenIdClaims(new JWTClaimsSet.Builder()
            .subject(SUBJECT)
            .issuer("https://idp.example.com")
            .build());
    }

    private static OpenIdTokenResponse tokenResponse() {
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse();
        tokenResponse.setAccessToken("access-token-test-fixture-not-a-secret");
        tokenResponse.setTokenType("Bearer");
        tokenResponse.setIdToken("id-token-test-fixture-not-a-secret");
        return tokenResponse;
    }

    private static Map<String, Object> config(String... providers) {
        Map<String, Object> config = new HashMap<>();
        config.put("micronaut.security.authentication", "cookie");
        for (String provider : providers) {
            String prefix = "micronaut.security.oauth2.clients." + provider;
            config.put(prefix + ".client-id", provider + "-client-id");
            config.put(prefix + ".client-secret", "test-fixture-not-a-secret");
            config.put(prefix + ".openid.issuer", "https://" + provider + ".example.com");
            config.put(prefix + ".openid.authorization.url", "https://" + provider + ".example.com/authorize");
            config.put(prefix + ".openid.token.url", "https://" + provider + ".example.com/token");
            config.put(prefix + ".openid.jwks-uri", "https://" + provider + ".example.com/certs");
        }
        return config;
    }
}
