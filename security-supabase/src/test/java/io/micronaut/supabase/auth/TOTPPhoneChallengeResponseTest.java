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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link TOTPPhoneChallengeResponse}.
 */
@MicronautTest(startApplication = false)
class TOTPPhoneChallengeResponseTest {

    private static final TOTPPhoneChallengeResponse SAMPLE = new TOTPPhoneChallengeResponse("8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", "totp", 1760715677);

    private static final String JSON = """
        {"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","type":"totp","expires_at":1760715677}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeTOTPPhoneChallengeResponseIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(TOTPPhoneChallengeResponse.class));
    }

    @Test
    void typeTOTPPhoneChallengeResponseIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(TOTPPhoneChallengeResponse.class)));
    }

    @Test
    void typeTOTPPhoneChallengeResponseIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(TOTPPhoneChallengeResponse.class)));
    }

    @Test
    void totpPhoneChallengeResponseJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void totpPhoneChallengeResponseJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(TOTPPhoneChallengeResponse.class)));
    }

    @Test
    void totpPhoneChallengeResponseSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "type", "expiresAt"})
    void typeTOTPPhoneChallengeResponseFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "type"})
    void typeTOTPPhoneChallengeResponseFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
