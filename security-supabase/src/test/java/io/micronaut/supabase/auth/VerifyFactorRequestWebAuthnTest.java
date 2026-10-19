package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.VerifyFactorRequest;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link VerifyFactorRequest.WebAuthn}.
 */
@MicronautTest(startApplication = false)
class VerifyFactorRequestWebAuthnTest {

    private static final VerifyFactorRequest.WebAuthn SAMPLE = new VerifyFactorRequest.WebAuthn("create", Map.of("id", "credential-id"));

    private static final String JSON = """
        {"type":"create","credential_response":{"id":"credential-id"}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeWebAuthnIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(VerifyFactorRequest.WebAuthn.class));
    }

    @Test
    void typeWebAuthnIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(VerifyFactorRequest.WebAuthn.class)));
    }

    @Test
    void typeWebAuthnIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(VerifyFactorRequest.WebAuthn.class)));
    }

    @Test
    void webAuthnJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void webAuthnJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(VerifyFactorRequest.WebAuthn.class)));
    }

    @Test
    void webAuthnSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"type", "credentialResponse"})
    void typeWebAuthnFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"type"})
    void typeWebAuthnFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
