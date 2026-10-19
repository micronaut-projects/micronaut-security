package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.TokenRequest;
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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link TokenRequest}.
 */
@MicronautTest(startApplication = false)
class TokenRequestTest {

    private static final TokenRequest SAMPLE = new TokenRequest(
        "refresh-token",
        "correct-horse-battery",
        "alice@example.com",
        "+15555550100",
        "id-token",
        "access-token",
        "nonce-value",
        "github",
        "d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60",
        "https://idp.example.com",
        new GoTrueSecurity("captcha-token"),
        "auth-code",
        "code-verifier",
        "Sign in to Example App",
        "0xsignature",
        "ethereum"
    );

    private static final String JSON = """
        {"refresh_token":"refresh-token","password":"correct-horse-battery","email":"alice@example.com","phone":"+15555550100","id_token":"id-token","access_token":"access-token","nonce":"nonce-value","provider":"github","client_id":"d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60","issuer":"https://idp.example.com","gotrue_meta_security":{"captcha_token":"captcha-token"},"auth_code":"auth-code","code_verifier":"code-verifier","message":"Sign in to Example App","signature":"0xsignature","chain":"ethereum"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeTokenRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(TokenRequest.class));
    }

    @Test
    void typeTokenRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(TokenRequest.class)));
    }

    @Test
    void typeTokenRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(TokenRequest.class)));
    }

    @Test
    void tokenRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void tokenRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(TokenRequest.class)));
    }

    @Test
    void tokenRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "refreshToken",
        "password",
        "email",
        "phone",
        "idToken",
        "accessToken",
        "nonce",
        "provider",
        "clientId",
        "issuer",
        "security",
        "authCode",
        "codeVerifier",
        "message",
        "signature",
        "chain"
    })
    void typeTokenRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
