package io.micronaut.security.oauth2.endpoint.token.response;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.jwt.validator.JwtAuthenticationFactory;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The provider-qualified username produced by {@link DefaultOpenIdAuthenticationMapper} must survive the credential the
 * application issues at login. The mapper keeps the raw {@code sub} as an attribute, and that attribute must not replace
 * the qualified principal in the {@code sub} claim of the generated JWT, otherwise later requests are reconstructed with
 * the unqualified name and the cross-provider collision comes back.
 */
class DefaultOpenIdAuthenticationMapperTokenRoundTripTest {

    private static final String SUBJECT = "alice";
    private static final String PROVIDER_A = "provider-a";
    private static final String PROVIDER_B = "provider-b";

    @Test
    void sameSubjectAtTwoProvidersStaysDistinctAfterTokenRoundTrip() throws ParseException {
        try (ApplicationContext context = ApplicationContext.run(config(PROVIDER_A, PROVIDER_B))) {
            DefaultOpenIdAuthenticationMapper mapper = context.getBean(DefaultOpenIdAuthenticationMapper.class);
            AccessRefreshTokenGenerator tokenGenerator = context.getBean(AccessRefreshTokenGenerator.class);
            JwtAuthenticationFactory authenticationFactory = context.getBean(JwtAuthenticationFactory.class);

            Authentication loginAtA = map(mapper, PROVIDER_A);
            Authentication loginAtB = map(mapper, PROVIDER_B);
            assertNotEquals(loginAtA.getName(), loginAtB.getName());

            Authentication requestAtA = roundTrip(tokenGenerator, authenticationFactory, loginAtA);
            Authentication requestAtB = roundTrip(tokenGenerator, authenticationFactory, loginAtB);

            assertEquals(PROVIDER_A + ":" + SUBJECT, requestAtA.getName());
            assertEquals(PROVIDER_B + ":" + SUBJECT, requestAtB.getName());
            assertNotEquals(requestAtA.getName(), requestAtB.getName(), "same sub at two providers must stay two users after the token round trip");
            assertEquals(PROVIDER_A, requestAtA.getAttributes().get(OauthAuthenticationMapper.PROVIDER_KEY));
            assertEquals(PROVIDER_B, requestAtB.getAttributes().get(OauthAuthenticationMapper.PROVIDER_KEY));
        }
    }

    private static Authentication roundTrip(AccessRefreshTokenGenerator tokenGenerator,
                                            JwtAuthenticationFactory authenticationFactory,
                                            Authentication authentication) throws ParseException {
        AccessRefreshToken token = tokenGenerator.generate(authentication).get();
        JWT jwt = JWTParser.parse(token.getAccessToken());
        assertEquals(authentication.getName(), jwt.getJWTClaimsSet().getClaim(JwtClaims.SUBJECT));
        return authenticationFactory.createAuthentication(jwt).get();
    }

    private static Authentication map(DefaultOpenIdAuthenticationMapper mapper, String providerName) {
        AuthenticationResponse response = mapper.createAuthenticationResponse(providerName, tokenResponse(), claims(), null);
        return response.getAuthentication().get();
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
        config.put("micronaut.security.token.jwt.signatures.secret.generator.secret", "test-fixture-not-a-secret-test-fixture-not-a-secret");
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
