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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link SignupResponse.User}.
 */
@MicronautTest(startApplication = false)
class SignupResponseUserTest {

    private static final SignupResponse.User SAMPLE = new SignupResponse.User(
        "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
        "authenticated",
        "authenticated",
        "alice@example.com",
        "+15555550100",
        Map.of("provider", "email"),
        Map.of("display_name", "Alice"),
        List.of(Map.of("provider", "email")),
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z",
        true
    );

    private static final String JSON = """
        {"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","aud":"authenticated","role":"authenticated","email":"alice@example.com","phone":"+15555550100","app_metadata":{"provider":"email"},"user_metadata":{"display_name":"Alice"},"identities":[{"provider":"email"}],"created_at":"2026-10-17T15:41:17Z","updated_at":"2026-10-17T15:41:17Z","confirmed_at":"2026-10-17T15:41:17Z","email_confirmed_at":"2026-10-17T15:41:17Z","phone_confirmed_at":"2026-10-17T15:41:17Z","confirmation_sent_at":"2026-10-17T15:41:17Z","last_sign_in_at":"2026-10-17T15:41:17Z","is_anonymous":true}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeUserIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(SignupResponse.User.class));
    }

    @Test
    void typeUserIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(SignupResponse.User.class)));
    }

    @Test
    void typeUserIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(SignupResponse.User.class)));
    }

    @Test
    void userJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void userJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(SignupResponse.User.class)));
    }

    @Test
    void userSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "id",
        "aud",
        "role",
        "email",
        "phone",
        "appMetadata",
        "userMetadata",
        "identities",
        "createdAt",
        "updatedAt",
        "confirmedAt",
        "emailConfirmedAt",
        "phoneConfirmedAt",
        "confirmationSentAt",
        "lastSignInAt",
        "isAnonymous"
    })
    void typeUserFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
