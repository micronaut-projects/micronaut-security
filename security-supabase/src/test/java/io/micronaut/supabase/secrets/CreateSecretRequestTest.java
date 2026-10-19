package io.micronaut.supabase.secrets;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.Records;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.Validator;
import jakarta.inject.Inject;
import jakarta.validation.ConstraintViolation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link CreateSecretRequest}.
 */
@MicronautTest(startApplication = false)
class CreateSecretRequestTest {

    private static final CreateSecretRequest SAMPLE = new CreateSecretRequest("OPENAI_API_KEY", "sk-example-secret");

    private static final String JSON = """
        {"name":"OPENAI_API_KEY","value":"sk-example-secret"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeCreateSecretRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(CreateSecretRequest.class));
    }

    @Test
    void typeCreateSecretRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(CreateSecretRequest.class)));
    }

    @Test
    void typeCreateSecretRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(CreateSecretRequest.class)));
    }

    @Test
    void createSecretRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void createSecretRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(CreateSecretRequest.class)));
    }

    @Test
    void createSecretRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"name", "value"})
    void typeCreateSecretRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"name"})
    void typeCreateSecretRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }

    @Test
    void createSecretRequestValueMayBeEmpty() {
        assertTrue(validator.validate(Records.with(SAMPLE, "value", "")).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"SUPABASE_URL", "SUPABASE_", "SUPABASE_SERVICE_ROLE_KEY"})
    void namesWithTheReservedPrefixAreRejected(String name) {
        Set<ConstraintViolation<CreateSecretRequest>> violations = validator.validate(Records.with(SAMPLE, "name", name));

        assertEquals(1, violations.size(), name);
        assertEquals("must not start with SUPABASE_", violations.iterator().next().getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"MY_SUPABASE_URL", "supabase_url", "SUPABASEURL", "OPENAI_API_KEY"})
    void namesWithoutTheReservedPrefixAreAccepted(String name) {
        assertTrue(validator.validate(Records.with(SAMPLE, "name", name)).isEmpty(), name);
    }

    @Test
    void nameIsLimitedTo256Characters() {
        assertTrue(validator.validate(Records.with(SAMPLE, "name", "A".repeat(CreateSecretRequest.NAME_MAX_LENGTH))).isEmpty());
        assertFalse(validator.validate(Records.with(SAMPLE, "name", "A".repeat(CreateSecretRequest.NAME_MAX_LENGTH + 1))).isEmpty());
    }

    @Test
    void valueIsLimitedTo24576Characters() {
        assertTrue(validator.validate(Records.with(SAMPLE, "value", "v".repeat(CreateSecretRequest.VALUE_MAX_LENGTH))).isEmpty());
        assertFalse(validator.validate(Records.with(SAMPLE, "value", "v".repeat(CreateSecretRequest.VALUE_MAX_LENGTH + 1))).isEmpty());
    }
}
