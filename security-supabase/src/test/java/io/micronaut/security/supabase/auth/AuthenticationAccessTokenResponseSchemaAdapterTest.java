package io.micronaut.security.supabase.auth;

import io.micronaut.security.authentication.AccessRefreshTokenAuthentication;
import io.micronaut.supabase.auth.AccessTokenResponseSchema;
import io.micronaut.supabase.auth.UserSchema;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthenticationAccessTokenResponseSchemaAdapterTest {
    private static final String ID = "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c";
    private static final UserSchema USER = new UserSchema(ID, "authenticated", "authenticated", "alice@example.com",
        null, null, null, null, null, null, null, null, null, null, null, null,
        Map.of("provider", "email"), null, null, null, null, null, null, null, false);
    private static final AccessTokenResponseSchema RESPONSE = new AccessTokenResponseSchema(
        "header.payload.signature", "opaque-refresh", "bearer", 3600, 1760000000, null, USER);

    @Test
    void tokensComeFromTheResponse() {
        AccessRefreshTokenAuthentication authentication = new AuthenticationAccessTokenResponseSchemaAdapter(RESPONSE);

        assertEquals("header.payload.signature", authentication.getAccessToken());
        assertEquals("opaque-refresh", authentication.getRefreshToken());
        assertEquals(3600, authentication.getExpiresIn());
    }

    @Test
    void principalComesFromTheEmbeddedUser() {
        AccessRefreshTokenAuthentication authentication = new AuthenticationAccessTokenResponseSchemaAdapter(RESPONSE);

        assertEquals(ID, authentication.getName());
        assertEquals(List.of("authenticated"), List.copyOf(authentication.getRoles()));
        assertEquals("alice@example.com", authentication.getAttributes().get("email"));
        assertInstanceOf(AuthenticationUserSchemaAdapter.class, authentication.getAuthentication());
    }

    @Test
    void tokensAreNotAttributes() {
        AccessRefreshTokenAuthentication authentication = new AuthenticationAccessTokenResponseSchemaAdapter(RESPONSE);

        assertFalse(authentication.getAttributes().containsValue("header.payload.signature"));
        assertFalse(authentication.getAttributes().containsValue("opaque-refresh"));
    }

    @Test
    void responseIsAccessible() {
        AuthenticationAccessTokenResponseSchemaAdapter authentication = new AuthenticationAccessTokenResponseSchemaAdapter(RESPONSE);

        assertSame(RESPONSE, authentication.getResponse());
    }

    @Test
    void missingTokensAreNull() {
        AccessTokenResponseSchema response = new AccessTokenResponseSchema(null, null, null, null, null, null, USER);
        AccessRefreshTokenAuthentication authentication = new AuthenticationAccessTokenResponseSchemaAdapter(response);

        assertNull(authentication.getAccessToken());
        assertNull(authentication.getRefreshToken());
        assertNull(authentication.getExpiresIn());
    }

    @Test
    void responseWithoutUserIsRejected() {
        AccessTokenResponseSchema response = new AccessTokenResponseSchema("a.b.c", "r", "bearer", 3600, null, null, null);

        assertThrows(IllegalArgumentException.class, () -> new AuthenticationAccessTokenResponseSchemaAdapter(response));
    }

    @Test
    void userWithoutIdentifierIsRejected() {
        UserSchema anonymous = new UserSchema(null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null);
        AccessTokenResponseSchema response = new AccessTokenResponseSchema("a.b.c", "r", "bearer", 3600, null, null, anonymous);

        assertThrows(IllegalArgumentException.class, () -> new AuthenticationAccessTokenResponseSchemaAdapter(response));
    }
}
