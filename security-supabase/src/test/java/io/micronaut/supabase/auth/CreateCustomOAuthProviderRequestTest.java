package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.CreateCustomOAuthProviderRequest;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import io.micronaut.validation.validator.Validator;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link CreateCustomOAuthProviderRequest}.
 */
@MicronautTest(startApplication = false)
class CreateCustomOAuthProviderRequestTest {

    private static final CreateCustomOAuthProviderRequest SAMPLE = new CreateCustomOAuthProviderRequest(
        "oauth2",
        "custom:acme",
        "mail",
        "d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60",
        "client-secret-fixture",
        List.of("other-client-id"),
        List.of("openid", "email"),
        true,
        Map.of("email", "email"),
        List.of("groups"),
        Map.of("prompt", "consent"),
        true,
        true,
        "https://idp.example.com",
        "https://idp.example.com/.well-known/openid-configuration",
        true,
        "https://idp.example.com/oauth/authorize",
        "https://idp.example.com/oauth/token",
        "https://idp.example.com/userinfo",
        "https://idp.example.com/.well-known/jwks.json"
    );

    private static final String JSON = """
        {"provider_type":"oauth2","identifier":"custom:acme","name":"mail","client_id":"d3b07384-d9a0-4c8e-9f1a-1b2c3d4e5f60","client_secret":"client-secret-fixture","acceptable_client_ids":["other-client-id"],"scopes":["openid","email"],"pkce_enabled":true,"attribute_mapping":{"email":"email"},"custom_claims_allowlist":["groups"],"authorization_params":{"prompt":"consent"},"enabled":true,"email_optional":true,"issuer":"https://idp.example.com","discovery_url":"https://idp.example.com/.well-known/openid-configuration","skip_nonce_check":true,"authorization_url":"https://idp.example.com/oauth/authorize","token_url":"https://idp.example.com/oauth/token","userinfo_url":"https://idp.example.com/userinfo","jwks_uri":"https://idp.example.com/.well-known/jwks.json"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeCreateCustomOAuthProviderRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(CreateCustomOAuthProviderRequest.class));
    }

    @Test
    void typeCreateCustomOAuthProviderRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(CreateCustomOAuthProviderRequest.class)));
    }

    @Test
    void typeCreateCustomOAuthProviderRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(CreateCustomOAuthProviderRequest.class)));
    }

    @Test
    void createCustomOAuthProviderRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void createCustomOAuthProviderRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(CreateCustomOAuthProviderRequest.class)));
    }

    @Test
    void createCustomOAuthProviderRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "acceptableClientIds",
        "scopes",
        "pkceEnabled",
        "attributeMapping",
        "customClaimsAllowlist",
        "authorizationParams",
        "enabled",
        "emailOptional",
        "issuer",
        "discoveryUrl",
        "skipNonceCheck",
        "authorizationUrl",
        "tokenUrl",
        "userinfoUrl",
        "jwksUri"
    })
    void typeCreateCustomOAuthProviderRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "providerType",
        "identifier",
        "name",
        "clientId",
        "clientSecret"
    })
    void typeCreateCustomOAuthProviderRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "providerType",
        "identifier",
        "name",
        "clientId",
        "clientSecret"
    })
    void typeCreateCustomOAuthProviderRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
