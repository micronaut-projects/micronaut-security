package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.OAuthClientRegistrationRequest;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link OAuthClientRegistrationRequest}.
 */
@MicronautTest(startApplication = false)
class OAuthClientRegistrationRequestTest {

    private static final OAuthClientRegistrationRequest SAMPLE = new OAuthClientRegistrationRequest(
        "Example App",
        "https://app.example.com",
        "https://app.example.com/logo.png",
        List.of("https://app.example.com/callback"),
        "confidential",
        "client_secret_post",
        List.of("authorization_code", "refresh_token"),
        List.of("code"),
        "openid email"
    );

    private static final String JSON = """
        {"client_name":"Example App","client_uri":"https://app.example.com","logo_uri":"https://app.example.com/logo.png","redirect_uris":["https://app.example.com/callback"],"client_type":"confidential","token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"openid email"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeOAuthClientRegistrationRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(OAuthClientRegistrationRequest.class));
    }

    @Test
    void typeOAuthClientRegistrationRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(OAuthClientRegistrationRequest.class)));
    }

    @Test
    void typeOAuthClientRegistrationRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(OAuthClientRegistrationRequest.class)));
    }

    @Test
    void oauthClientRegistrationRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void oauthClientRegistrationRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(OAuthClientRegistrationRequest.class)));
    }

    @Test
    void oauthClientRegistrationRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "clientUri",
        "logoUri",
        "clientType",
        "tokenEndpointAuthMethod",
        "grantTypes",
        "responseTypes",
        "scope"
    })
    void typeOAuthClientRegistrationRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"clientName", "redirectUris"})
    void typeOAuthClientRegistrationRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"clientName"})
    void typeOAuthClientRegistrationRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"redirectUris"})
    void typeOAuthClientRegistrationRequestFieldCannotBeEmpty(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, List.of())).isEmpty(), property);
    }
}
