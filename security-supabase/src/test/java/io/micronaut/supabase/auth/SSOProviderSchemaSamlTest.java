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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link SSOProviderSchema.Saml}.
 */
@MicronautTest(startApplication = false)
class SSOProviderSchemaSamlTest {

    private static final SSOProviderSchema.Saml SAMPLE = new SSOProviderSchema.Saml(
        "https://idp.example.com",
        "<EntityDescriptor/>",
        "https://idp.example.com/metadata",
        new SAMLAttributeMappingSchema(
            Map.of("email", new SAMLAttributeMappingSchema.AttributeMapping("mail", List.of("mail", "email"), "guest"))
        )
    );

    private static final String JSON = """
        {"entity_id":"https://idp.example.com","metadata_xml":"<EntityDescriptor/>","metadata_url":"https://idp.example.com/metadata","attribute_mapping":{"keys":{"email":{"name":"mail","names":["mail","email"],"default":"guest"}}}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeSamlIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(SSOProviderSchema.Saml.class));
    }

    @Test
    void typeSamlIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(SSOProviderSchema.Saml.class)));
    }

    @Test
    void typeSamlIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(SSOProviderSchema.Saml.class)));
    }

    @Test
    void samlJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void samlJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(SSOProviderSchema.Saml.class)));
    }

    @Test
    void samlSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"entityId", "metadataXml", "metadataUrl", "attributeMapping"})
    void typeSamlFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
