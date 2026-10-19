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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link MFAFactorSchema}.
 */
@MicronautTest(startApplication = false)
class MFAFactorSchemaTest {

    private static final MFAFactorSchema SAMPLE = new MFAFactorSchema(
        "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
        "verified",
        "Authenticator",
        "totp",
        "credential-id",
        "+15555550100",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z"
    );

    private static final String JSON = """
        {"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","status":"verified","friendly_name":"Authenticator","factor_type":"totp","webauthn_credential":"credential-id","phone":"+15555550100","created_at":"2026-10-17T15:41:17Z","updated_at":"2026-10-17T15:41:17Z","last_challenged_at":"2026-10-17T15:41:17Z"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeMFAFactorSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(MFAFactorSchema.class));
    }

    @Test
    void typeMFAFactorSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(MFAFactorSchema.class)));
    }

    @Test
    void typeMFAFactorSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(MFAFactorSchema.class)));
    }

    @Test
    void mfaFactorSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void mfaFactorSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(MFAFactorSchema.class)));
    }

    @Test
    void mfaFactorSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "id",
        "status",
        "friendlyName",
        "factorType",
        "webauthnCredential",
        "phone",
        "createdAt",
        "updatedAt",
        "lastChallengedAt"
    })
    void typeMFAFactorSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
