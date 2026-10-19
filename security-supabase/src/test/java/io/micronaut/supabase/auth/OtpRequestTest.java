package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.OtpRequest;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link OtpRequest}.
 */
@MicronautTest(startApplication = false)
class OtpRequestTest {

    private static final OtpRequest SAMPLE = new OtpRequest(
        "alice@example.com",
        "+15555550100",
        "sms",
        true,
        Map.of("display_name", "Alice"),
        "s256",
        "code-challenge",
        new GoTrueSecurity("captcha-token")
    );

    private static final String JSON = """
        {"email":"alice@example.com","phone":"+15555550100","channel":"sms","create_user":true,"data":{"display_name":"Alice"},"code_challenge_method":"s256","code_challenge":"code-challenge","gotrue_meta_security":{"captcha_token":"captcha-token"}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeOtpRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(OtpRequest.class));
    }

    @Test
    void typeOtpRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(OtpRequest.class)));
    }

    @Test
    void typeOtpRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(OtpRequest.class)));
    }

    @Test
    void otpRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void otpRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(OtpRequest.class)));
    }

    @Test
    void otpRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "email",
        "phone",
        "channel",
        "createUser",
        "data",
        "codeChallengeMethod",
        "codeChallenge",
        "security"
    })
    void typeOtpRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
