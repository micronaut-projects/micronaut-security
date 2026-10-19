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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link SSOProviderSchema}.
 */
@MicronautTest(startApplication = false)
class SSOProviderSchemaTest {

    private static final SSOProviderSchema SAMPLE = new SSOProviderSchema(
        "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c",
        List.of(new SSOProviderSchema.SsoDomain("example.com")),
        new SSOProviderSchema.Saml(
            "https://idp.example.com",
            "<EntityDescriptor/>",
            "https://idp.example.com/metadata",
            new SAMLAttributeMappingSchema(
                Map.of("email", new SAMLAttributeMappingSchema.AttributeMapping("mail", List.of("mail", "email"), "guest"))
            )
        )
    );

    private static final String JSON = """
        {"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","domains":[{"domain":"example.com"}],"saml":{"entity_id":"https://idp.example.com","metadata_xml":"<EntityDescriptor/>","metadata_url":"https://idp.example.com/metadata","attribute_mapping":{"keys":{"email":{"name":"mail","names":["mail","email"],"default":"guest"}}}}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeSSOProviderSchemaIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(SSOProviderSchema.class));
    }

    @Test
    void typeSSOProviderSchemaIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(SSOProviderSchema.class)));
    }

    @Test
    void typeSSOProviderSchemaIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(SSOProviderSchema.class)));
    }

    @Test
    void ssoProviderSchemaJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void ssoProviderSchemaJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(SSOProviderSchema.class)));
    }

    @Test
    void ssoProviderSchemaSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"id", "ssoDomains", "saml"})
    void typeSSOProviderSchemaFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
