package io.micronaut.security.token.jwt.validator;

import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;
import io.micronaut.security.token.jwt.generator.JwtTokenGenerator;
import org.junit.jupiter.params.ParameterizedTest;
import reactor.core.publisher.Mono;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * The {@code iss} claim must match the configured issuer exactly. A token whose {@code iss} is merely a suffix or a
 * parent domain of the configured issuer (down to the empty string), or differs in scheme, case or trailing slash, must be rejected.
 */
class IssuerJwtClaimsValidatorSuffixTest {

    private static final String SECRET = "test-fixture-not-a-secret-0123456789";

    static Stream<Arguments> rejected() {
        return Stream.of(
                arguments("admin-portal", "portal"),
                arguments("admin-portal", "l"),
                arguments("admin-portal", ""),
                arguments("admin-portal", "/"),
                arguments("admin-portal", "https://"),
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
                // parent domains are not accepted either
                arguments("https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com", "https://identity.oraclecloud.com/"),
                arguments("https://idcs-227ebfb7094445cc5a3fbc0faa1fe87b.identity.oraclecloud.com", "https://identity.oraclecloud.com"),
                // host, port, userinfo and double trailing slash are compared verbatim; opaque issuers are case-sensitive
                arguments("https://auth.example.com", "https://AUTH.example.com"),
                arguments("https://auth.example.com", "https://auth.example.com:443"),
                arguments("https://auth.example.com", "https://evil.com@auth.example.com"),
                arguments("https://auth.example.com", "https://auth.example.com//"),
                arguments("admin-portal", "Admin-Portal"),
                arguments("admin-portal", "admin-portal/"),
                arguments("https://issuer.example?tenant=TenantA", "https://issuer.example?tenant=tenanta"),
                arguments("https://TenantA@issuer.example", "https://tenanta@issuer.example"),
                arguments("https://auth.example.com", "http\u017F://auth.example.com"),
                arguments("https://issuer.example?tenant=TenantA", "https://issuer.example?tenant=TenantA/"),
                // on this branch the comparison is verbatim: scheme, case and trailing slash are part of the issuer
                arguments("https://auth.example.com", "HTTPS://auth.example.com"),
                arguments("https://auth.example.com", "auth.example.com"),
                arguments("https://auth.example.com/", "https://auth.example.com"),
                arguments("https://auth.example.com", "https://auth.example.com/"));
    }

    static Stream<Arguments> accepted() {
        return Stream.of(
                arguments("admin-portal", "admin-portal"),
                arguments("https://auth.example.com", "https://auth.example.com"),
                arguments("https://auth.example.com/", "https://auth.example.com/"),
                arguments("https://auth.example.com/realms/master", "https://auth.example.com/realms/master"));
    }

    @ParameterizedTest
    @MethodSource("rejected")
    void tokenWithSuffixIssuerIsRejected(String configuredIssuer, String issuer) {
        try (ApplicationContext context = ApplicationContext.run(configuration(configuredIssuer))) {
            Optional<Authentication> result = authenticate(context, generateJwtWithIssuer(context, issuer));
            assertFalse(result.isPresent(), () -> "iss '" + issuer + "' must not satisfy configured issuer '" + configuredIssuer + "'");
        }
    }

    @ParameterizedTest
    @MethodSource("accepted")
    void tokenWithMatchingIssuerIsAccepted(String configuredIssuer, String issuer) {
        try (ApplicationContext context = ApplicationContext.run(configuration(configuredIssuer))) {
            Optional<Authentication> result = authenticate(context, generateJwtWithIssuer(context, issuer));
            assertTrue(result.isPresent(), () -> "iss '" + issuer + "' must satisfy configured issuer '" + configuredIssuer + "'");
            assertEquals("alice", result.get().getName());
        }
    }

    private static Map<String, Object> configuration(String configuredIssuer) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("micronaut.security.token.jwt.signatures.secret.generator.secret", SECRET);
        configuration.put(IssuerJwtClaimsValidator.ISSUER_PROP, configuredIssuer);
        return configuration;
    }

    private static Optional<Authentication> authenticate(ApplicationContext context, String jwt) {
        JwtTokenValidator jwtValidator = context.getBean(JwtTokenValidator.class);
        return Mono.from(jwtValidator.validateToken(jwt, null)).blockOptional();
    }

    private static String generateJwtWithIssuer(ApplicationContext context, String issuer) {
        JwtTokenGenerator jwtGenerator = context.getBean(JwtTokenGenerator.class);
        Map<String, Object> claims = new HashMap<>();
        claims.put(JwtClaims.SUBJECT, "alice");
        claims.put(JwtClaims.ISSUER, issuer);
        return jwtGenerator.generateToken(claims).get();
    }
}
