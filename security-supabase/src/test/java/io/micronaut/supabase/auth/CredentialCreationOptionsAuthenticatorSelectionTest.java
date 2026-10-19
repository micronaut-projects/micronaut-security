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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link CredentialCreationOptions.AuthenticatorSelection}.
 */
@MicronautTest(startApplication = false)
class CredentialCreationOptionsAuthenticatorSelectionTest {

    private static final CredentialCreationOptions.AuthenticatorSelection SAMPLE = new CredentialCreationOptions.AuthenticatorSelection(
        "platform",
        true,
        "preferred",
        "preferred"
    );

    private static final String JSON = """
        {"authenticatorAttachment":"platform","requireResidentKey":true,"residentKey":"preferred","userVerification":"preferred"}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeAuthenticatorSelectionIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(CredentialCreationOptions.AuthenticatorSelection.class));
    }

    @Test
    void typeAuthenticatorSelectionIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(CredentialCreationOptions.AuthenticatorSelection.class)));
    }

    @Test
    void typeAuthenticatorSelectionIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(CredentialCreationOptions.AuthenticatorSelection.class)));
    }

    @Test
    void authenticatorSelectionJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void authenticatorSelectionJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(CredentialCreationOptions.AuthenticatorSelection.class)));
    }

    @Test
    void authenticatorSelectionSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"authenticatorAttachment", "requireResidentKey", "residentKey", "userVerification"})
    void typeAuthenticatorSelectionFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }
}
