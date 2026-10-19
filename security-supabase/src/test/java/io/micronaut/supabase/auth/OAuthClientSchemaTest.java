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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link OAuthClientSchema}.
 */
@MicronautTest(startApplication = false)
class OAuthClientSchemaTest {

    private static final OAuthClientSchema SAMPLE = new OAuthClientSchema(
        "d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60",
        "Example App",
        "client-secret-fixture",
        "confidential",
        "client_secret_post",
        "manual",
        "https://app.example.com",
        "https://app.example.com/logo.png",
        List.of("https://app.example.com/callback"),
        List.of("authorization_code", "refresh_token"),
        List.of("code"),
        "openid email",
        "2026-10-17T15:41:17Z",
        "2026-10-17T15:41:17Z"
    );

    private static final String JSON = """
        {"client_id":"d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60","client_name":"Example App","client_secret":"client-secret-fixture","client_type":"confidential","token_endpoint_auth_method":"client_secret_post","registration_type":"manual","client_uri":"https://app.example.com","logo_uri":"https://app.example.com/logo.png","redirect_uris":["https://app.example.com/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"openid email","created_at":"2026-10-17T15:41:17Z","updated_at":"2026-10-17T15:41:17Z"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeOAuthClientSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(OAuthClientSchema.class));
    }

    @Test
    void typeOAuthClientSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(OAuthClientSchema.class)));
    }

    @Test
    void typeOAuthClientSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(OAuthClientSchema.class)));
    }

    @Test
    void oauthClientSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void oauthClientSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(OAuthClientSchema.class)));
    }

    @Test
    void oauthClientSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "clientId",
        "clientName",
        "clientSecret",
        "clientType",
        "tokenEndpointAuthMethod",
        "registrationType",
        "clientUri",
        "logoUri",
        "redirectUris",
        "grantTypes",
        "responseTypes",
        "scope",
        "createdAt",
        "updatedAt"
    })
    void typeOAuthClientSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
