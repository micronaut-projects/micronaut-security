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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link MFARecoveryCodesStatusSchema}.
 */
@MicronautTest(startApplication = false)
class MFARecoveryCodesStatusSchemaTest {

    private static final MFARecoveryCodesStatusSchema SAMPLE = new MFARecoveryCodesStatusSchema(
        "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
        "recovery_code",
        10,
        9
    );

    private static final String JSON = """
        {"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","type":"recovery_code","total":10,"remaining":9}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeMFARecoveryCodesStatusSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(MFARecoveryCodesStatusSchema.class));
    }

    @Test
    void typeMFARecoveryCodesStatusSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(MFARecoveryCodesStatusSchema.class)));
    }

    @Test
    void typeMFARecoveryCodesStatusSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(MFARecoveryCodesStatusSchema.class)));
    }

    @Test
    void mfaRecoveryCodesStatusSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void mfaRecoveryCodesStatusSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(MFARecoveryCodesStatusSchema.class)));
    }

    @Test
    void mfaRecoveryCodesStatusSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "type", "total", "remaining"})
    void typeMFARecoveryCodesStatusSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
