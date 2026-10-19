package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.SsoRequest;
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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link SsoRequest}.
 */
@MicronautTest(startApplication = false)
class SsoRequestTest {

    private static final SsoRequest SAMPLE = new SsoRequest(
        "example.com",
        "9c1d2b3f-4a5e-6d7c-8f7c-1a3e6d2b4e9a",
        "http://localhost:3000/welcome",
        true,
        "code-challenge",
        "s256",
        new GoTrueSecurity("captcha-token")
    );

    private static final String JSON = """
        {"domain":"example.com","provider_id":"9c1d2b3f-4a5e-6d7c-8f7c-1a3e6d2b4e9a","redirect_to":"http://localhost:3000/welcome","skip_http_redirect":true,"code_challenge":"code-challenge","code_challenge_method":"s256","gotrue_meta_security":{"captcha_token":"captcha-token"}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeSsoRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(SsoRequest.class));
    }

    @Test
    void typeSsoRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(SsoRequest.class)));
    }

    @Test
    void typeSsoRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(SsoRequest.class)));
    }

    @Test
    void ssoRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void ssoRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(SsoRequest.class)));
    }

    @Test
    void ssoRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "domain",
        "providerId",
        "redirectTo",
        "skipHttpRedirect",
        "codeChallenge",
        "codeChallengeMethod",
        "security"
    })
    void typeSsoRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
