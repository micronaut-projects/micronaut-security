package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.Validator;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link AccessTokenResponseSchema}.
 */
@MicronautTest(startApplication = false)
class AccessTokenResponseSchemaTest {

    private static final AccessTokenResponseSchema SAMPLE = new AccessTokenResponseSchema(
        "access-token",
        "refresh-token",
        "bearer",
        3600,
        1760715677,
        new AccessTokenResponseSchema.WeakPassword(List.of("length"), "Password is too short"),
        new UserSchema(
            "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
            "authenticated",
            "authenticated",
            "alice@example.com",
            "2026-10-17T15:41:17Z",
            "+15555550100",
            "2026-10-17T15:41:17Z",
            "2026-10-17T15:41:17Z",
            "2026-10-17T15:41:17Z",
            "2026-10-17T15:41:17Z",
            "alice.new@example.com",
            "2026-10-17T15:41:17Z",
            "+15555550101",
            "2026-10-17T15:41:17Z",
            "2026-10-17T15:41:17Z",
            "2026-10-17T15:41:17Z",
            Map.of("provider", "email"),
            Map.of("display_name", "Alice"),
            List.of(new MFAFactorSchema(
                "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
                "verified",
                "Authenticator",
                "totp",
                "credential-id",
                "+15555550100",
                "2026-10-17T15:41:17Z",
                "2026-10-17T15:41:17Z",
                "2026-10-17T15:41:17Z"
            )),
            List.of(new IdentitySchema(
                "2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b",
                "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
                "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
                Map.of("sub", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c"),
                "github",
                "2026-10-17T15:41:17Z",
                "2026-10-17T15:41:17Z",
                "2026-10-17T15:41:17Z",
                "alice@example.com"
            )),
            "2026-10-17T15:41:17Z",
            "2026-10-17T15:41:17Z",
            "2026-10-17T15:41:17Z",
            "2026-10-17T15:41:17Z",
            true
        )
    );

    private static final String JSON = """
        {"access_token":"access-token","refresh_token":"refresh-token","token_type":"bearer","expires_in":3600,"expires_at":1760715677,"weak_password":{"reasons":["length"],"message":"Password is too short"},"user":{"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","aud":"authenticated","role":"authenticated","email":"alice@example.com","email_confirmed_at":"2026-10-17T15:41:17Z","phone":"+15555550100","phone_confirmed_at":"2026-10-17T15:41:17Z","confirmation_sent_at":"2026-10-17T15:41:17Z","confirmed_at":"2026-10-17T15:41:17Z","recovery_sent_at":"2026-10-17T15:41:17Z","new_email":"alice.new@example.com","email_change_sent_at":"2026-10-17T15:41:17Z","new_phone":"+15555550101","phone_change_sent_at":"2026-10-17T15:41:17Z","reauthentication_sent_at":"2026-10-17T15:41:17Z","last_sign_in_at":"2026-10-17T15:41:17Z","app_metadata":{"provider":"email"},"user_metadata":{"display_name":"Alice"},"factors":[{"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","status":"verified","friendly_name":"Authenticator","factor_type":"totp","webauthn_credential":"credential-id","phone":"+15555550100","created_at":"2026-10-17T15:41:17Z","updated_at":"2026-10-17T15:41:17Z","last_challenged_at":"2026-10-17T15:41:17Z"}],"identities":[{"identity_id":"2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b","id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","user_id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","identity_data":{"sub":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c"},"provider":"github","last_sign_in_at":"2026-10-17T15:41:17Z","created_at":"2026-10-17T15:41:17Z","updated_at":"2026-10-17T15:41:17Z","email":"alice@example.com"}],"banned_until":"2026-10-17T15:41:17Z","created_at":"2026-10-17T15:41:17Z","updated_at":"2026-10-17T15:41:17Z","deleted_at":"2026-10-17T15:41:17Z","is_anonymous":true}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeAccessTokenResponseSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(AccessTokenResponseSchema.class));
    }

    @Test
    void typeAccessTokenResponseSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(AccessTokenResponseSchema.class)));
    }

    @Test
    void typeAccessTokenResponseSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(AccessTokenResponseSchema.class)));
    }

    @Test
    void accessTokenResponseSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void accessTokenResponseSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(AccessTokenResponseSchema.class)));
    }

    @Test
    void accessTokenResponseSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "accessToken",
        "refreshToken",
        "tokenType",
        "expiresIn",
        "expiresAt",
        "weakPassword",
        "user"
    })
    void typeAccessTokenResponseSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
