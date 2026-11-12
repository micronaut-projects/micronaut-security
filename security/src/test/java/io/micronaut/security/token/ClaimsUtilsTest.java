package io.micronaut.security.token;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class ClaimsUtilsTest {

    static Stream<Arguments> paramsProvider() {
        return Stream.of(
                arguments("https://identity.oraclecloud.com", "identity.oraclecloud.com"),
                arguments("https://identity.oraclecloud.com/", "identity.oraclecloud.com"),
                arguments("http://identity.oraclecloud.com/", "identity.oraclecloud.com"),
                arguments("identity.oraclecloud.com", "identity.oraclecloud.com"),
                // only a leading scheme (and a single trailing slash) is stripped
                arguments("https://auth.example.com/https://", "auth.example.com/https:/"),
                arguments("https://auth.example.com?x/", "auth.example.com?x/"),
                arguments("https://auth.example.com#x/", "auth.example.com#x/"),
                arguments("https://auth.example.com/http://x", "auth.example.com/http://x"));
    }

    static Stream<Arguments> matchingParamsProvider() {
        return Stream.of(
                // exact matches ignoring scheme and trailing slash
                arguments("https://auth.example.com", "https://auth.example.com"),
                arguments("https://auth.example.com/", "https://auth.example.com"),
                arguments("https://auth.example.com", "https://auth.example.com/"),
                arguments("http://auth.example.com", "https://auth.example.com"),
                arguments("https://auth.example.com", "auth.example.com"),
                arguments("https://identity.oraclecloud.com", "https://identity.oraclecloud.com"),
                arguments("https://identity.oraclecloud.com/", "identity.oraclecloud.com"),
                arguments("https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abcdefghi/", "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abcdefghi"),
                arguments("http://localhost:8080/oauth2/default", "http://localhost:8080/oauth2/default"),
                arguments("https://auth.example.com/realms/master", "auth.example.com/realms/master"),
                // only the scheme is case-insensitive
                arguments("HTTPS://auth.example.com", "https://auth.example.com"),
                arguments("https://auth.example.com", "HTTPS://auth.example.com/"),
                arguments("https://Auth.Example.com", "https://Auth.Example.com"),
                arguments("admin-portal", "admin-portal"),
                arguments("TenantA", "TenantA"),
                arguments("urn:example:issuer", "urn:example:issuer"),
                arguments("http://10.0.0.1", "http://10.0.0.1"),
                arguments("http://10.0.0.1:8080", "http://10.0.0.1:8080"),
                arguments("https://issuer.example?tenant=TenantA", "https://issuer.example?tenant=TenantA"),
                arguments("https://issuer.example?tenant=TenantA/", "https://issuer.example?tenant=TenantA/"),
                arguments("https://issuer.example/?x", "https://issuer.example/?x"),
                arguments("https://TenantA@issuer.example/", "https://TenantA@issuer.example"),
                arguments("expected-issuer", "expected-issuer"));
    }

    static Stream<Arguments> nonMatchingParamsProvider() {
        return Stream.of(
                // suffixes of a non-URL issuer (GHSA-qr8w-hxv9-92gh reproducer)
                arguments("admin-portal", "portal"),
                arguments("admin-portal", "l"),
                arguments("admin-portal", ""),
                arguments("admin-portal", "/"),
                arguments("admin-portal", "https://"),
                arguments("https://auth.example.com", "com"),
                arguments("https://auth.example.com", ""),
                arguments("https://auth.example.com", " "),
                arguments("https://auth.example.com", "https://"),
                arguments("https://auth.example.com", "http://"),
                arguments("https://auth.example.com", "/"),
                arguments("https://auth.example.com", "."),
                arguments("https://auth.example.com", ".com"),
                arguments("https://auth.example.com", "example.com"),
                arguments("https://auth.example.com", "https://example.com"),
                arguments("https://auth.example.com", "https://auth.example.com.evil.com"),
                arguments("https://auth.example.com", "https://evil.auth.example.com"),
                arguments("https://auth.example.com", "a-different-issuer"),
                // parent domains are not accepted, not even for the Oracle IDCS tenant/provider pair: configure issuer-identifier instead
                arguments("https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com", "https://identity.oraclecloud.com/"),
                arguments("https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com", "https://identity.oraclecloud.com"),
                arguments("https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com/", "identity.oraclecloud.com"),
                arguments("https://idcs.identity.oraclecloud.com", "oraclecloud.com"),
                arguments("https://svc-a.internal.example.com", "https://internal.example.com"),
                arguments("https://a.b.auth.example.com", "b.auth.example.com"),
                arguments("https://tenant.us.auth0.com/", "https://us.auth0.com/"),
                arguments("https://a.b.auth.example.com", "a..b.auth.example.com"),
                // non label boundary suffix
                arguments("https://xexample.com", "example.com"),
                arguments("https://xexample.com", "https://example.com"),
                // scheme not at the start
                arguments("https://auth.example.com", "https://https://auth.example.com"),
                // path-only suffix
                arguments("https://auth.example.com/realms/master", "master"),
                arguments("https://auth.example.com/realms/master", "/realms/master"),
                arguments("https://auth.example.com/realms/master", "realms/master"),
                arguments("https://auth.example.com/realms/a.b", "a.b"),
                arguments("https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abcdefghi", "https://cognito-idp.eu-west-1.amazonaws.com"),
                arguments("https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abcdefghi", "https://amazonaws.com"),
                arguments("https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com", "https://identity.oraclecloud.com/foo"),
                // host, port, userinfo and path are case-sensitive
                arguments("https://auth.example.com", "https://AUTH.example.com"),
                arguments("https://Auth.Example.com", "https://auth.example.com"),
                arguments("https://Auth.example.com/", "http://auth.EXAMPLE.com"),
                arguments("https://auth.example.com/Realm", "https://auth.example.com/realm"),
                // query, fragment and userinfo are part of the issuer identifier and keep their case
                arguments("https://issuer.example?tenant=TenantA", "https://issuer.example?tenant=tenanta"),
                arguments("https://issuer.example#TenantA", "https://issuer.example#tenanta"),
                arguments("https://TenantA@issuer.example", "https://tenanta@issuer.example"),
                arguments("https://issuer.example/?tenant=TenantA", "https://issuer.example/?tenant=tenanta"),
                // a trailing slash is only ignored when it ends the path, not a query or a fragment
                arguments("https://issuer.example?tenant=TenantA", "https://issuer.example?tenant=TenantA/"),
                arguments("https://issuer.example?tenant=TenantA/", "https://issuer.example?tenant=TenantA"),
                arguments("https://issuer.example#TenantA", "https://issuer.example#TenantA/"),
                arguments("https://issuer.example?x", "https://issuer.example/?x"),
                arguments("https://issuer.example/?x", "https://issuer.example?x"),
                arguments("expected-issuer", "a-different-issuer"),
                arguments("expected-issuer", "issuer"),
                // port
                arguments("https://auth.example.com", "https://auth.example.com:443"),
                arguments("https://auth.example.com:443", "https://auth.example.com"),
                // userinfo
                arguments("https://auth.example.com", "https://auth.example.com@evil.com"),
                arguments("https://auth.example.com", "https://evil.com@auth.example.com"),
                // IP literals, with and without a port
                arguments("http://10.0.0.1", "0.0.1"),
                arguments("http://10.0.0.1:8080", "0.0.1:8080"),
                arguments("https://192.168.1.10", "168.1.10"),
                arguments("https://[::1]", "::1"),
                // query string and fragment
                arguments("https://a.b.example.com?x=1", "b.example.com?x=1"),
                arguments("https://auth.example.com", "https://auth.example.com?"),
                arguments("https://auth.example.com", "https://auth.example.com#"),
                // double trailing slash, dot segment, percent-encoded slash
                arguments("https://auth.example.com", "https://auth.example.com//"),
                arguments("https://auth.example.com//", "https://auth.example.com"),
                arguments("https://auth.example.com/realms/master", "https://auth.example.com/realms/./master"),
                arguments("https://auth.example.com/realms/master", "https://auth.example.com/realms%2Fmaster"),
                // trailing dot (FQDN) is not normalised
                arguments("https://auth.example.com", "auth.example.com."),
                arguments("https://auth.example.com.", "auth.example.com"),
                // opaque (non http(s)) issuers are StringOrURI values compared verbatim: no case folding, no trailing slash removal
                arguments("TenantA", "tenanta"),
                arguments("admin-portal", "Admin-Portal"),
                arguments("admin-portal", "admin-portal/"),
                arguments("admin-portal/", "admin-portal"),
                arguments("urn:example:issuer", "URN:example:issuer"),
                arguments("auth.example.com", "Auth.example.com"),
                arguments("https://auth.example.com", "Auth.example.com"),
                arguments("auth.example.com", "auth.example.com/"),
                arguments("https://auth.example.com/realms/master", "auth.example.com/realms/master/"),
                arguments("ftp://auth.example.com", "ftp://Auth.example.com"),
                // the scheme is matched ignoring ASCII case only: U+017F LATIN SMALL LETTER LONG S is not an "s"
                arguments("https://auth.example.com", "http\u017F://auth.example.com"),
                arguments("https://auth.example.com", "HTTP\u017F://auth.example.com"),
                arguments("admin-portal", "http\u017F://admin-portal"),
                // no unicode folding (Kelvin sign); surrounding whitespace or control characters are not ignored
                arguments("https://kauth.example.com", "https://\u212Aauth.example.com"),
                arguments("https://Kauth.example.com", "https://\u212Aauth.example.com"),
                arguments("https://auth.example.com", " https://auth.example.com"),
                arguments("https://auth.example.com", "https://auth.example.com "),
                arguments("https://auth.example.com", "https://auth.example.com\n"),
                arguments("https://auth.example.com", "https://auth.example.com\u0000"));
    }

    @ParameterizedTest
    @MethodSource("matchingParamsProvider")
    void equalsIgnoringProtocolAndTrailingSlash(String configClaim, String claim) {
        assertTrue(ClaimsUtils.equalsIgnoringProtocolAndTrailingSlash(configClaim, claim));
    }

    @ParameterizedTest
    @MethodSource("nonMatchingParamsProvider")
    void doesNotEqualIgnoringProtocolAndTrailingSlash(String configClaim, String claim) {
        assertFalse(ClaimsUtils.equalsIgnoringProtocolAndTrailingSlash(configClaim, claim));
    }

    @ParameterizedTest
    @MethodSource("nonMatchingParamsProvider")
    @SuppressWarnings("removal")
    void deprecatedEndsWithNoLongerAcceptsSuffixesOrParentDomains(String configClaim, String claim) {
        assertFalse(ClaimsUtils.endsWithIgnoringProtocolAndTrailingSlash(configClaim, claim));
    }

    @ParameterizedTest
    @MethodSource("matchingParamsProvider")
    @SuppressWarnings("removal")
    void deprecatedEndsWithStillAcceptsExactMatches(String configClaim, String claim) {
        assertTrue(ClaimsUtils.endsWithIgnoringProtocolAndTrailingSlash(configClaim, claim));
    }

    @ParameterizedTest
    @MethodSource("paramsProvider")
    void cleanupClaim(String claim, String expected) {
        assertEquals(expected, ClaimsUtils.removeLeadingProtocolAndTrailingSlash(claim));
    }
}
