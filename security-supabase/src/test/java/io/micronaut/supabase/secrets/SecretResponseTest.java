package io.micronaut.supabase.secrets;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.Records;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.Validator;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link SecretResponse}.
 */
@MicronautTest(startApplication = false)
class SecretResponseTest {

    private static final SecretResponse SAMPLE = new SecretResponse(
        "OPENAI_API_KEY",
        "sk-example-secret",
        "2026-10-18T09:15:00Z"
    );

    private static final String JSON = """
        {"name":"OPENAI_API_KEY","value":"sk-example-secret","updated_at":"2026-10-18T09:15:00Z"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeSecretResponseIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(SecretResponse.class));
    }

    @Test
    void typeSecretResponseIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(SecretResponse.class)));
    }

    @Test
    void typeSecretResponseIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(SecretResponse.class)));
    }

    @Test
    void secretResponseJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void secretResponseJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(SecretResponse.class)));
    }

    @Test
    void secretResponseWithoutUpdatedAtIsDeserialized() throws IOException {
        assertEquals(new SecretResponse("OPENAI_API_KEY", "sk-example-secret", null),
            jsonMapper.readValue("""
                {"name":"OPENAI_API_KEY","value":"sk-example-secret"}""", Argument.of(SecretResponse.class)));
    }

    @Test
    void secretResponseSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"updatedAt"})
    void typeSecretResponseFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"name", "value"})
    void typeSecretResponseFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"name"})
    void typeSecretResponseFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }

    @Test
    void secretResponseValueMayBeEmpty() {
        assertTrue(validator.validate(Records.with(SAMPLE, "value", "")).isEmpty());
    }
}
