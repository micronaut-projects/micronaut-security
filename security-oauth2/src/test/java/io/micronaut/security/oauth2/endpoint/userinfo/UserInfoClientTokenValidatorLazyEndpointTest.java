package io.micronaut.security.oauth2.endpoint.userinfo;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * A {@link UserInfoClientTokenValidator} whose endpoint is resolved lazily skips the token while the endpoint cannot be
 * resolved and retries the resolution on the next validation.
 */
class UserInfoClientTokenValidatorLazyEndpointTest {

    @Test
    void endpointResolutionFailureSkipsTheTokenAndIsRetried() {
        AtomicInteger resolutions = new AtomicInteger();
        UserInfoClientTokenValidator validator = new UserInfoClientTokenValidator("okta", false, () -> {
            resolutions.incrementAndGet();
            throw new IllegalStateException("metadata unavailable");
        });

        assertNull(Mono.from(validator.validateToken("token", null)).block());
        assertNull(Mono.from(validator.validateToken("token", null)).block());
        assertEquals(2, resolutions.get());
    }

    @Test
    void providerWithoutUserInfoEndpointSkipsTheTokenAndIsResolvedOnce() {
        AtomicInteger resolutions = new AtomicInteger();
        UserInfoClientTokenValidator validator = new UserInfoClientTokenValidator("okta", false, () -> {
            resolutions.incrementAndGet();
            return Optional.empty();
        });

        assertNull(Mono.from(validator.validateToken("token", null)).block());
        assertNull(Mono.from(validator.validateToken("token", null)).block());
        assertEquals(1, resolutions.get());
    }

    @Test
    void closingAValidatorWhoseEndpointWasNeverResolvedDoesNotResolveIt() {
        AtomicInteger resolutions = new AtomicInteger();
        UserInfoClientTokenValidator validator = new UserInfoClientTokenValidator("okta", false, () -> {
            resolutions.incrementAndGet();
            return Optional.empty();
        });

        validator.close();

        assertEquals(0, resolutions.get());
    }
}
