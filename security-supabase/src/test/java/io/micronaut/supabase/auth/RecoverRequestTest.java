package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.RecoverRequest;
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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link RecoverRequest}.
 */
@MicronautTest(startApplication = false)
class RecoverRequestTest {

    private static final RecoverRequest SAMPLE = new RecoverRequest(
        "alice@example.com",
        "code-challenge",
        "s256",
        new GoTrueSecurity("captcha-token")
    );

    private static final String JSON = """
        {"email":"alice@example.com","code_challenge":"code-challenge","code_challenge_method":"s256","gotrue_meta_security":{"captcha_token":"captcha-token"}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeRecoverRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(RecoverRequest.class));
    }

    @Test
    void typeRecoverRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(RecoverRequest.class)));
    }

    @Test
    void typeRecoverRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(RecoverRequest.class)));
    }

    @Test
    void recoverRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void recoverRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(RecoverRequest.class)));
    }

    @Test
    void recoverRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"codeChallenge", "codeChallengeMethod", "security"})
    void typeRecoverRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"email"})
    void typeRecoverRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"email"})
    void typeRecoverRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
