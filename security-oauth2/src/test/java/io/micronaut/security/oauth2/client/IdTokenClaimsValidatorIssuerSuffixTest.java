package io.micronaut.security.oauth2.client;

import io.micronaut.context.ApplicationContext;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.MapClaims;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
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
            Claims claims = new MapClaims(Map.of(Claims.ISSUER, iss, Claims.AUDIENCE, CLIENT_ID));
            assertFalse(validator(context).validate(claims, null));
        }
    }

    @ParameterizedTest
    @MethodSource("accepted")
    void validateAcceptsTokenWithMatchingIssuer(String configuredIssuer, String iss) {
        try (ApplicationContext context = context(configuredIssuer)) {
            Claims claims = new MapClaims(Map.of(Claims.ISSUER, iss, Claims.AUDIENCE, CLIENT_ID));
            assertTrue(validator(context).validate(claims, null));
        }
    }

    private static ApplicationContext context(String configuredIssuer) {
        return ApplicationContext.run(Map.of(
                "micronaut.security.oauth2.clients.oci.client-id", CLIENT_ID,
                "micronaut.security.oauth2.clients.oci.client-secret", "test-fixture-not-a-secret",
                "micronaut.security.oauth2.clients.oci.openid.issuer", configuredIssuer,
                "micronaut.security.oauth2.clients.oci.openid.fetch-configuration", "false"));
    }

    private static OpenIdClientConfiguration openId(ApplicationContext context) {
        return context.getBean(OauthClientConfiguration.class).getOpenid().orElseThrow();
    }

    private static IdTokenClaimsValidator<Object> validator(ApplicationContext context) {
        return new IdTokenClaimsValidator<>(List.of(context.getBean(OauthClientConfiguration.class)));
    }
}
