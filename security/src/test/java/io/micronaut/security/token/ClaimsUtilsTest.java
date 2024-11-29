package io.micronaut.security.token;

import junit.framework.TestCase;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;

public class ClaimsUtilsTest extends TestCase {

    static Stream<Arguments> paramsProvider() {
        return Stream.of(
                arguments("https://identity.oraclecloud.com", "identity.oraclecloud.com"),
                arguments("https://identity.oraclecloud.com/", "identity.oraclecloud.com"),
                arguments("http://identity.oraclecloud.com/", "identity.oraclecloud.com"),
                arguments("identity.oraclecloud.com", "identity.oraclecloud.com"));
    }

    static Stream<Arguments> startsWithParamsProvider() {
        return Stream.of(
                arguments("https://idcs-214ecfa9143532ca8c3fba0ecb1fe65b.identity.oraclecloud.com", "https://identity.oraclecloud.com/")
        );
    }

    @ParameterizedTest
    @MethodSource("startsWithParamsProvider")
    void endsWithIgnoring(String configClaim, String claim) {
        assertTrue(ClaimsUtils.endsWithIgnoringProtocolAndTrailingSlash(configClaim, claim));
    }

    @ParameterizedTest
    @MethodSource("paramsProvider")
    void cleanupClaim(String claim, String expected) {
        assertEquals(expected, ClaimsUtils.removeLeadingProtocolAndTrailingSlash(claim));
    }
}