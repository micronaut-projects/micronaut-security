package io.micronaut.security.event;

import io.micronaut.context.event.ApplicationEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class SecurityEventToStringTest {

    private static final String SENSITIVE = "sensitive-attributes-test-fixture-not-a-secret";

    private static final class CustomAuthentication {
        private final String refreshToken;

        private CustomAuthentication(String refreshToken) {
            this.refreshToken = refreshToken;
        }

        @Override
        public String toString() {
            return "CustomAuthentication[" + SENSITIVE + ", refreshToken=" + refreshToken + "]";
        }
    }

    @Test
    void loginSuccessfulEventDoesNotPrintTheSource() {
        LoginSuccessfulEvent event = new LoginSuccessfulEvent(new CustomAuthentication("rt"));
        assertRedacted(event, LoginSuccessfulEvent.class);
    }

    @Test
    void logoutEventDoesNotPrintTheSource() {
        LogoutEvent event = new LogoutEvent(new CustomAuthentication("rt"));
        assertRedacted(event, LogoutEvent.class);
    }

    @Test
    void loginFailedEventDoesNotPrintTheSource() {
        LoginFailedEvent event = new LoginFailedEvent(new CustomAuthentication("rt"));
        assertRedacted(event, LoginFailedEvent.class);
    }

    private static void assertRedacted(ApplicationEvent event, Class<?> type) {
        String str = event.toString();
        assertFalse(str.contains(SENSITIVE), () -> "source leaked in toString: " + str);
        assertFalse(str.contains("refreshToken"), () -> "source leaked in toString: " + str);
        assertEquals(type.getName() + "[source=<redacted>]", str);
    }
}
