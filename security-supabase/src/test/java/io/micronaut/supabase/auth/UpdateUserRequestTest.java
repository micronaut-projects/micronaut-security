package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.UpdateUserRequest;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.Validator;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link UpdateUserRequest}.
 */
@MicronautTest(startApplication = false)
class UpdateUserRequestTest {

    private static final UpdateUserRequest SAMPLE = new UpdateUserRequest(
        "alice@example.com",
        "+15555550100",
        "correct-horse-battery",
        "nonce-value",
        Map.of("display_name", "Alice"),
        Map.of("provider", "email"),
        "sms"
    );

    private static final String JSON = """
        {"email":"alice@example.com","phone":"+15555550100","password":"correct-horse-battery","nonce":"nonce-value","data":{"display_name":"Alice"},"app_metadata":{"provider":"email"},"channel":"sms"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeUpdateUserRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(UpdateUserRequest.class));
    }

    @Test
    void typeUpdateUserRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(UpdateUserRequest.class)));
    }

    @Test
    void typeUpdateUserRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(UpdateUserRequest.class)));
    }

    @Test
    void updateUserRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void updateUserRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(UpdateUserRequest.class)));
    }

    @Test
    void updateUserRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "email",
        "phone",
        "password",
        "nonce",
        "data",
        "appMetadata",
        "channel"
    })
    void typeUpdateUserRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
