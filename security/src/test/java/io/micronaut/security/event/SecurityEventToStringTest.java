package io.micronaut.security.event;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class SecurityEventToStringTest {

    private static final String SENSITIVE = "sensitive-attributes-test-fixture-not-a-secret";

    private record CustomAuthentication(String refreshToken) {
        @Override
        public String toString() {
            return "CustomAuthentication[" + SENSITIVE + ", refreshToken=" + refreshToken + "]";
        }
    }

    @Test
    void loginSuccessfulEventDoesNotPrintTheSource() {
        LoginSuccessfulEvent event = new LoginSuccessfulEvent(new CustomAuthentication("rt"), "localhost", Locale.ENGLISH);
        assertRedacted(event, LoginSuccessfulEvent.class);
    }

    @Test
    void logoutEventDoesNotPrintTheSource() {
        LogoutEvent event = new LogoutEvent(new CustomAuthentication("rt"), "localhost", Locale.ENGLISH);
        assertRedacted(event, LogoutEvent.class);
    }

    private static void assertRedacted(SecurityEvent event, Class<?> type) {
        String str = event.toString();
        assertFalse(str.contains(SENSITIVE), () -> "source leaked in toString: " + str);
        assertFalse(str.contains("refreshToken"), () -> "source leaked in toString: " + str);
        assertEquals(type.getName() + "[source=<redacted>]", str);
    }
}
