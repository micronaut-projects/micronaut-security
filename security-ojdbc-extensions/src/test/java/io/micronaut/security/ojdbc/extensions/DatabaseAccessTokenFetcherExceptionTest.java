package io.micronaut.security.ojdbc.extensions;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class DatabaseAccessTokenFetcherExceptionTest {

    @Test
    void constructorSetsMessage() {
        DatabaseAccessTokenFetcherException exception = new DatabaseAccessTokenFetcherException("Failed to fetch token");

        assertEquals("Failed to fetch token", exception.getMessage());
        assertNull(exception.getCause());
    }

    @Test
    void constructorSetsMessageAndCause() {
        IllegalStateException cause = new IllegalStateException("Missing required provider parameter: clientId");

        DatabaseAccessTokenFetcherException exception = new DatabaseAccessTokenFetcherException("Failed to fetch token", cause);

        assertEquals("Failed to fetch token", exception.getMessage());
        assertSame(cause, exception.getCause());
    }
}
