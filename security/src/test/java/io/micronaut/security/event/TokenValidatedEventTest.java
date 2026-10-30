package io.micronaut.security.event;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenValidatedEventTest {
    private static final String TOKEN = "validated-token-test-fixture-not-a-secret";

    @Test
    void sourceExposesTheValidatedToken() {
        TokenValidatedEvent event = new TokenValidatedEvent(TOKEN, "localhost", Locale.ENGLISH);
        assertEquals(TOKEN, event.getSource());
        assertEquals("localhost", event.getHost().orElse(null));
        assertEquals(Locale.ENGLISH, event.getLocale());
    }

    @Test
    void toStringDoesNotExposeTheValidatedToken() {
        TokenValidatedEvent event = new TokenValidatedEvent(TOKEN, "localhost", Locale.ENGLISH);
        String str = event.toString();
        assertFalse(str.contains(TOKEN), () -> "token leaked in toString: " + str);
        assertTrue(str.contains(TokenValidatedEvent.class.getName()));
        assertTrue(str.contains("<redacted>"));
    }
}
