package io.micronaut.security.supabase.auth;

import io.micronaut.security.authentication.Authentication;
import io.micronaut.supabase.auth.IdentitySchema;
import io.micronaut.supabase.auth.UserSchema;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationUserSchemaAdapterTest {
    private static final String ID = "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c";
    private static final UserSchema USER = new UserSchema(ID, "authenticated", "authenticated", "alice@example.com",
        "2026-10-17T15:41:17Z", null, null, null, "2026-10-17T15:41:17Z", null, null, null, null, null, null,
        "2026-10-17T15:41:17Z", Map.of("provider", "email"), Map.of("display_name", "Alice"), null,
        List.of(new IdentitySchema(null, ID, ID, null, "email", null, null, null, "alice@example.com")),
        null, "2026-10-17T15:41:17Z", "2026-10-17T15:41:17Z", null, false);

    @Test
    void nameIsTheUserId() {
        Authentication authentication = new AuthenticationUserSchemaAdapter(USER);

        assertEquals(ID, authentication.getName());
    }

    @Test
    void attributesAreTheUserFieldsUnderTheirJsonNames() {
        Map<String, Object> attributes = new AuthenticationUserSchemaAdapter(USER).getAttributes();

        assertEquals(ID, attributes.get("id"));
        assertEquals("alice@example.com", attributes.get("email"));
        assertEquals("2026-10-17T15:41:17Z", attributes.get("email_confirmed_at"));
        assertEquals("2026-10-17T15:41:17Z", attributes.get("last_sign_in_at"));
        assertEquals(Map.of("provider", "email"), attributes.get("app_metadata"));
        assertEquals(Map.of("display_name", "Alice"), attributes.get("user_metadata"));
        assertEquals(USER.identities(), attributes.get("identities"));
        assertEquals(false, attributes.get("is_anonymous"));
    }

    @Test
    void nullFieldsAreNotAttributes() {
        Map<String, Object> attributes = new AuthenticationUserSchemaAdapter(USER).getAttributes();

        assertFalse(attributes.containsKey("phone"));
        assertFalse(attributes.containsKey("factors"));
        assertFalse(attributes.containsKey("banned_until"));
        assertFalse(attributes.containsKey("deleted_at"));
    }

    @Test
    void attributesAreUnmodifiable() {
        Map<String, Object> attributes = new AuthenticationUserSchemaAdapter(USER).getAttributes();

        assertThrows(UnsupportedOperationException.class, () -> attributes.put("email", "bob@example.com"));
    }

    @Test
    void supabaseRoleIsTheOnlyRole() {
        assertEquals(List.of("authenticated"), List.copyOf(new AuthenticationUserSchemaAdapter(USER).getRoles()));
    }

    @Test
    void userWithoutRoleHasNoRoles() {
        UserSchema user = new UserSchema(ID, null, null, "alice@example.com", null, null, null, null, null, null, null, null,
            null, null, null, null, null, null, null, null, null, null, null, null, null);

        assertTrue(new AuthenticationUserSchemaAdapter(user).getRoles().isEmpty());
    }

    @Test
    void nullUserHasNoNameAttributesOrRoles() {
        AuthenticationUserSchemaAdapter authentication = new AuthenticationUserSchemaAdapter(null);

        assertNull(authentication.getName());
        assertNull(authentication.getUser());
        assertTrue(authentication.getAttributes().isEmpty());
        assertTrue(authentication.getRoles().isEmpty());
    }

    @Test
    void adaptedUserIsExposed() {
        assertSame(USER, new AuthenticationUserSchemaAdapter(USER).getUser());
    }
}
