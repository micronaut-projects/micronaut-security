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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link MFARecoveryCodesSchema}.
 */
@MicronautTest(startApplication = false)
class MFARecoveryCodesSchemaTest {

    private static final MFARecoveryCodesSchema SAMPLE = new MFARecoveryCodesSchema(
        "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
        "recovery_code",
        "Authenticator",
        10,
        List.of("abcd-efgh-ijkl-mnop", "qrst-uvwx-yzab-cdef")
    );

    private static final String JSON = """
        {"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","type":"recovery_code","friendly_name":"Authenticator","total":10,"codes":["abcd-efgh-ijkl-mnop","qrst-uvwx-yzab-cdef"]}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeMFARecoveryCodesSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(MFARecoveryCodesSchema.class));
    }

    @Test
    void typeMFARecoveryCodesSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(MFARecoveryCodesSchema.class)));
    }

    @Test
    void typeMFARecoveryCodesSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(MFARecoveryCodesSchema.class)));
    }

    @Test
    void mfaRecoveryCodesSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void mfaRecoveryCodesSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(MFARecoveryCodesSchema.class)));
    }

    @Test
    void mfaRecoveryCodesSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "id",
        "type",
        "friendlyName",
        "total",
        "codes"
    })
    void typeMFARecoveryCodesSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
