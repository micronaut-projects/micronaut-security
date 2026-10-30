package io.micronaut.security.event;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenValidatedEventTest {
    private static final String TOKEN = "validated-token-test-fixture-not-a-secret";

    @Test
    void sourceExposesTheValidatedToken() {
        TokenValidatedEvent event = new TokenValidatedEvent(TOKEN);
        assertEquals(TOKEN, event.getSource());
    }

    @Test
    void toStringDoesNotExposeTheValidatedToken() {
        TokenValidatedEvent event = new TokenValidatedEvent(TOKEN);
        String str = event.toString();
        assertFalse(str.contains(TOKEN), () -> "token leaked in toString: " + str);
        assertTrue(str.contains(TokenValidatedEvent.class.getName()));
        assertTrue(str.contains("<redacted>"));
    }
}
