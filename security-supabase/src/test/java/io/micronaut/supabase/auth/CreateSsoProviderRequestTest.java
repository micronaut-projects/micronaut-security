package io.micronaut.supabase.auth;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.SupabaseAuthRequests.CreateSsoProviderRequest;
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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link CreateSsoProviderRequest}.
 */
@MicronautTest(startApplication = false)
class CreateSsoProviderRequestTest {

    private static final CreateSsoProviderRequest SAMPLE = new CreateSsoProviderRequest(
        "saml",
        "https://idp.example.com/metadata",
        "<EntityDescriptor/>",
        List.of("example.com"),
        new SAMLAttributeMappingSchema(
            Map.of("email", new SAMLAttributeMappingSchema.AttributeMapping("mail", List.of("mail", "email"), "guest"))
        )
    );

    private static final String JSON = """
        {"type":"saml","metadata_url":"https://idp.example.com/metadata","metadata_xml":"<EntityDescriptor/>","domains":["example.com"],"attribute_mapping":{"keys":{"email":{"name":"mail","names":["mail","email"],"default":"guest"}}}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeCreateSsoProviderRequestIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(CreateSsoProviderRequest.class));
    }

    @Test
    void typeCreateSsoProviderRequestIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(CreateSsoProviderRequest.class)));
    }

    @Test
    void typeCreateSsoProviderRequestIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(CreateSsoProviderRequest.class)));
    }

    @Test
    void createSsoProviderRequestJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void createSsoProviderRequestJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(CreateSsoProviderRequest.class)));
    }

    @Test
    void createSsoProviderRequestSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"metadataUrl", "metadataXml", "domains", "attributeMapping"})
    void typeCreateSsoProviderRequestFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"type"})
    void typeCreateSsoProviderRequestFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"type"})
    void typeCreateSsoProviderRequestFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
