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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link AccessTokenResponseSchema.WeakPassword}.
 */
@MicronautTest(startApplication = false)
class AccessTokenResponseSchemaWeakPasswordTest {

    private static final AccessTokenResponseSchema.WeakPassword SAMPLE = new AccessTokenResponseSchema.WeakPassword(List.of("length"), "Password is too short");

    private static final String JSON = """
        {"reasons":["length"],"message":"Password is too short"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeWeakPasswordIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(AccessTokenResponseSchema.WeakPassword.class));
    }

    @Test
    void typeWeakPasswordIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(AccessTokenResponseSchema.WeakPassword.class)));
    }

    @Test
    void typeWeakPasswordIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(AccessTokenResponseSchema.WeakPassword.class)));
    }

    @Test
    void weakPasswordJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void weakPasswordJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(AccessTokenResponseSchema.WeakPassword.class)));
    }

    @Test
    void weakPasswordSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"reasons", "message"})
    void typeWeakPasswordFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
