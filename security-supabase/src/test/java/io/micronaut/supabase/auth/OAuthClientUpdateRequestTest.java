package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.OAuthClientUpdateRequest;
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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link OAuthClientUpdateRequest}.
 */
@MicronautTest(startApplication = false)
class OAuthClientUpdateRequestTest {

    private static final OAuthClientUpdateRequest SAMPLE = new OAuthClientUpdateRequest(
        "Example App",
        "https://app.example.com",
        "https://app.example.com/logo.png",
        List.of("https://app.example.com/callback"),
        List.of("authorization_code", "refresh_token"),
        "client_secret_post"
    );

    private static final String JSON = """
        {"client_name":"Example App","client_uri":"https://app.example.com","logo_uri":"https://app.example.com/logo.png","redirect_uris":["https://app.example.com/callback"],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"client_secret_post"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeOAuthClientUpdateRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(OAuthClientUpdateRequest.class));
    }

    @Test
    void typeOAuthClientUpdateRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(OAuthClientUpdateRequest.class)));
    }

    @Test
    void typeOAuthClientUpdateRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(OAuthClientUpdateRequest.class)));
    }

    @Test
    void oauthClientUpdateRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void oauthClientUpdateRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(OAuthClientUpdateRequest.class)));
    }

    @Test
    void oauthClientUpdateRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "clientName",
        "clientUri",
        "logoUri",
        "redirectUris",
        "grantTypes",
        "tokenEndpointAuthMethod"
    })
    void typeOAuthClientUpdateRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
