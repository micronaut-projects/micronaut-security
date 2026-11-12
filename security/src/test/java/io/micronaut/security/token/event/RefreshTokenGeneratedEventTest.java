package io.micronaut.security.token.event;

import io.micronaut.security.authentication.Authentication;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RefreshTokenGeneratedEventTest {
    private static final String REFRESH_TOKEN = "refresh-token-test-fixture-not-a-secret";

    @Test
    void accessorsExposeTheRefreshTokenAndAuthentication() {
        Authentication authentication = Authentication.build("sherlock");
        RefreshTokenGeneratedEvent event = new RefreshTokenGeneratedEvent(authentication, REFRESH_TOKEN);
        assertEquals(REFRESH_TOKEN, event.getRefreshToken());
        assertEquals(REFRESH_TOKEN, event.getSource());
        assertEquals(authentication, event.getAuthentication());
    }

    @Test
    void toStringDoesNotExposeTheRefreshToken() {
        RefreshTokenGeneratedEvent event = new RefreshTokenGeneratedEvent(Authentication.build("sherlock"), REFRESH_TOKEN);
        String str = event.toString();
        assertFalse(str.contains(REFRESH_TOKEN), () -> "token leaked in toString: " + str);
        assertTrue(str.contains(RefreshTokenGeneratedEvent.class.getName()));
        assertTrue(str.contains("<redacted>"));
    }
}
