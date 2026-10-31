package io.micronaut.security.oauth2.client;

import io.micronaut.context.ApplicationContext;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * The ID token {@code iss} claim must be identical to the expected OpenID client issuer (OpenID Connect Core 1.0 section 3.1.3.7);
 * only the case of the scheme and a trailing slash are tolerated. A different scheme, a different host case, a suffix or a parent
 * domain of the configured issuer (down to the empty string) must be rejected.
 */
class IdTokenClaimsValidatorIssuerSuffixTest {

    private static final String CLIENT_ID = "test-client-id";

    static Stream<Arguments> rejected() {
        return Stream.of(
                arguments("https://auth.example.com", "com"),
                arguments("https://auth.example.com", ""),
                arguments("https://auth.example.com", "https://"),
                arguments("https://auth.example.com", "/"),
                arguments("https://auth.example.com", "example.com"),
                arguments("https://auth.example.com", "https://example.com"),
                arguments("https://auth.example.com", "https://auth.example.com.evil.com"),
                arguments("https://xexample.com", "example.com"),
                arguments("https://auth.example.com/realms/master", "master"),
                arguments("https://auth.example.com/realms/master", "https://auth.example.com"),
                // parent domains are not accepted: Oracle IDCS users configure openid.issuer-identifier with the provider wide issuer
                arguments("https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com", "https://identity.oraclecloud.com/"),
                arguments("https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com", "https://identity.oraclecloud.com"),
                arguments("https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com", "https://identity.oraclecloud.com/foo"),
                arguments("https://svc-a.internal.example.com", "https://internal.example.com"),
                arguments("http://10.0.0.1:8080", "0.0.1:8080"),
                // the scheme is part of the issuer identifier
                arguments("https://auth.example.com", "http://auth.example.com"),
                arguments("http://auth.example.com", "https://auth.example.com"),
                arguments("https://auth.example.com", "auth.example.com"),
                // the host is compared case-sensitively
                arguments("https://auth.example.com", "https://Auth.example.com"),
                // port, userinfo and a double trailing slash are part of the issuer identifier
                arguments("https://auth.example.com", "https://auth.example.com:443"),
                arguments("https://auth.example.com", "https://auth.example.com@evil.com"),
                arguments("https://auth.example.com", "https://evil.com@auth.example.com"),
                arguments("https://auth.example.com", "https://auth.example.com//"));
    }

    static Stream<Arguments> accepted() {
        return Stream.of(
                arguments("https://identity.oraclecloud.com", "https://identity.oraclecloud.com"),
                arguments("https://identity.oraclecloud.com/", "https://identity.oraclecloud.com"),
                arguments("https://auth.example.com", "https://auth.example.com/"),
                arguments("https://auth.example.com", "HTTPS://auth.example.com"),
                arguments("https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abcdefghi/", "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abcdefghi"));
    }

    @ParameterizedTest
    @MethodSource("rejected")
    void matchesIssuerRejectsSuffix(String configuredIssuer, String iss) {
        try (ApplicationContext context = context(configuredIssuer)) {
            OpenIdClientConfiguration openId = openId(context);
            Optional<Boolean> result = validator(context).matchesIssuer(openId, iss);
            assertTrue(result.isPresent());
            assertEquals(Boolean.FALSE, result.get(), () -> "iss '" + iss + "' must not match configured issuer '" + configuredIssuer + "'");
        }
    }

    @ParameterizedTest
    @MethodSource("accepted")
    void matchesIssuerAcceptsIdenticalIssuer(String configuredIssuer, String iss) {
        try (ApplicationContext context = context(configuredIssuer)) {
            OpenIdClientConfiguration openId = openId(context);
            Optional<Boolean> result = validator(context).matchesIssuer(openId, iss);
            assertTrue(result.isPresent());
            assertEquals(Boolean.TRUE, result.get(), () -> "iss '" + iss + "' must match configured issuer '" + configuredIssuer + "'");
        }
    }

    @ParameterizedTest
    @MethodSource("rejected")
    void validateRejectsTokenWithSuffixIssuer(String configuredIssuer, String iss) {
        try (ApplicationContext context = context(configuredIssuer)) {
            JwtClaimsSetAdapter claims = new JwtClaimsSetAdapter(new JWTClaimsSet.Builder().issuer(iss).audience(CLIENT_ID).build());
            assertFalse(validator(context).validate(claims, null));
        }
    }

    @ParameterizedTest
    @MethodSource("accepted")
    void validateAcceptsTokenWithMatchingIssuer(String configuredIssuer, String iss) {
        try (ApplicationContext context = context(configuredIssuer)) {
            JwtClaimsSetAdapter claims = new JwtClaimsSetAdapter(new JWTClaimsSet.Builder().issuer(iss).audience(CLIENT_ID).build());
            assertTrue(validator(context).validate(claims, null));
        }
    }

    private static ApplicationContext context(String configuredIssuer) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("micronaut.security.oauth2.clients.oci.client-id", CLIENT_ID);
        configuration.put("micronaut.security.oauth2.clients.oci.client-secret", "test-fixture-not-a-secret");
        // on this branch discovery is fetched at startup: point it at a closed port so it fails fast, and put the
        // issuer under test in issuer-identifier, which is the value the validator compares the iss claim with
        configuration.put("micronaut.security.oauth2.clients.oci.openid.issuer", "http://localhost:1/oauth2/default");
        configuration.put("micronaut.security.oauth2.clients.oci.openid.issuer-identifier", configuredIssuer);
        return ApplicationContext.run(configuration);
    }

    private static OpenIdClientConfiguration openId(ApplicationContext context) {
        return context.getBean(OauthClientConfiguration.class).getOpenid().get();
    }

    private static IdTokenClaimsValidator validator(ApplicationContext context) {
        return new IdTokenClaimsValidator(Collections.singletonList(context.getBean(OauthClientConfiguration.class)));
    }
}
