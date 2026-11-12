package io.micronaut.security.token.event;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessTokenGeneratedEventTest {
    private static final String ACCESS_TOKEN = "access-token-test-fixture-not-a-secret";

    @Test
    void sourceExposesTheAccessToken() {
        AccessTokenGeneratedEvent event = new AccessTokenGeneratedEvent(ACCESS_TOKEN);
        assertEquals(ACCESS_TOKEN, event.getSource());
    }

    @Test
    void toStringDoesNotExposeTheAccessToken() {
        AccessTokenGeneratedEvent event = new AccessTokenGeneratedEvent(ACCESS_TOKEN);
        String str = event.toString();
        assertFalse(str.contains(ACCESS_TOKEN), () -> "token leaked in toString: " + str);
        assertTrue(str.contains(AccessTokenGeneratedEvent.class.getName()));
        assertTrue(str.contains("<redacted>"));
    }
}
