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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link WebAuthnChallengeResponse}.
 */
@MicronautTest(startApplication = false)
class WebAuthnChallengeResponseTest {

    private static final WebAuthnChallengeResponse SAMPLE = new WebAuthnChallengeResponse(
        "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
        "webauthn",
        1760715677,
        Map.of("challenge", "Y2hhbGxlbmdl")
    );

    private static final String JSON = """
        {"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","type":"webauthn","expires_at":1760715677,"webauthn":{"challenge":"Y2hhbGxlbmdl"}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeWebAuthnChallengeResponseIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(WebAuthnChallengeResponse.class));
    }

    @Test
    void typeWebAuthnChallengeResponseIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(WebAuthnChallengeResponse.class)));
    }

    @Test
    void typeWebAuthnChallengeResponseIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(WebAuthnChallengeResponse.class)));
    }

    @Test
    void webAuthnChallengeResponseJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void webAuthnChallengeResponseJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(WebAuthnChallengeResponse.class)));
    }

    @Test
    void webAuthnChallengeResponseSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"expiresAt"})
    void typeWebAuthnChallengeResponseFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "type", "webauthn"})
    void typeWebAuthnChallengeResponseFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "type"})
    void typeWebAuthnChallengeResponseFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
