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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link IdentitySchema}.
 */
@MicronautTest(startApplication = false)
class IdentitySchemaTest {

    private static final IdentitySchema SAMPLE = new IdentitySchema(
        "2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b",
        "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
        "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
        Map.of("sub", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c"),
        "github",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z",
        "alice@example.com"
    );

    private static final String JSON = """
        {"identity_id":"2b3f4a5e-6d7c-4e9a-9c1d-8f7c1a3e6d2b","id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","user_id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","identity_data":{"sub":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c"},"provider":"github","last_sign_in_at":"2026-10-17T15:41:17Z","created_at":"2026-10-17T15:41:17Z","updated_at":"2026-10-17T15:41:17Z","email":"alice@example.com"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeIdentitySchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(IdentitySchema.class));
    }

    @Test
    void typeIdentitySchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(IdentitySchema.class)));
    }

    @Test
    void typeIdentitySchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(IdentitySchema.class)));
    }

    @Test
    void identitySchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void identitySchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(IdentitySchema.class)));
    }

    @Test
    void identitySchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "identityId",
        "id",
        "userId",
        "identityData",
        "provider",
        "lastSignInAt",
        "createdAt",
        "updatedAt",
        "email"
    })
    void typeIdentitySchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
