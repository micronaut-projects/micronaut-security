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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link PublicKeyCredentialDescriptor}.
 */
@MicronautTest(startApplication = false)
class PublicKeyCredentialDescriptorTest {

    private static final PublicKeyCredentialDescriptor SAMPLE = new PublicKeyCredentialDescriptor("public-key", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", List.of("internal"));

    private static final String JSON = """
        {"type":"public-key","id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","transports":["internal"]}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typePublicKeyCredentialDescriptorIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(PublicKeyCredentialDescriptor.class));
    }

    @Test
    void typePublicKeyCredentialDescriptorIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(PublicKeyCredentialDescriptor.class)));
    }

    @Test
    void typePublicKeyCredentialDescriptorIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(PublicKeyCredentialDescriptor.class)));
    }

    @Test
    void publicKeyCredentialDescriptorJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void publicKeyCredentialDescriptorJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(PublicKeyCredentialDescriptor.class)));
    }

    @Test
    void publicKeyCredentialDescriptorSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"transports"})
    void typePublicKeyCredentialDescriptorFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"type", "id"})
    void typePublicKeyCredentialDescriptorFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"type", "id"})
    void typePublicKeyCredentialDescriptorFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
