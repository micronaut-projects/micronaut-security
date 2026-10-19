package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.OAuthTokenRequest;
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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link OAuthTokenRequest}.
 */
@MicronautTest(startApplication = false)
class OAuthTokenRequestTest {

    private static final OAuthTokenRequest SAMPLE = new OAuthTokenRequest(
        "authorization_code",
        "auth-code",
        "https://app.example.com/callback",
        "code-verifier",
        "refresh-token",
        "d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60",
        "client-secret-fixture"
    );

    private static final String JSON = """
        {"grant_type":"authorization_code","code":"auth-code","redirect_uri":"https://app.example.com/callback","code_verifier":"code-verifier","refresh_token":"refresh-token","client_id":"d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60","client_secret":"client-secret-fixture"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeOAuthTokenRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(OAuthTokenRequest.class));
    }

    @Test
    void typeOAuthTokenRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(OAuthTokenRequest.class)));
    }

    @Test
    void typeOAuthTokenRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(OAuthTokenRequest.class)));
    }

    @Test
    void oauthTokenRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void oauthTokenRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(OAuthTokenRequest.class)));
    }

    @Test
    void oauthTokenRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "code",
        "redirectUri",
        "codeVerifier",
        "refreshToken",
        "clientId",
        "clientSecret"
    })
    void typeOAuthTokenRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"grantType"})
    void typeOAuthTokenRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"grantType"})
    void typeOAuthTokenRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }

    @Test
    void toMapOmitsNullFields() {
        OAuthTokenRequest request = new OAuthTokenRequest("refresh_token", null, null, null, "refresh-token", "d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60", null);

        assertEquals(Map.of(
            "grant_type", "refresh_token",
            "refresh_token", "refresh-token",
            "client_id", "d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60"), request.toMap());
    }
}
