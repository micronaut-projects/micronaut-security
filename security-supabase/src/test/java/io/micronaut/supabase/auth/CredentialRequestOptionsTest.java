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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link CredentialRequestOptions}.
 */
@MicronautTest(startApplication = false)
class CredentialRequestOptionsTest {

    private static final CredentialRequestOptions SAMPLE = new CredentialRequestOptions(
        "Y2hhbGxlbmdl",
        60000,
        "example.com",
        List.of(new PublicKeyCredentialDescriptor("public-key", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", List.of("internal"))),
        "preferred",
        List.of("security-key"),
        Map.of("credProps", "true")
    );

    private static final String JSON = """
        {"challenge":"Y2hhbGxlbmdl","timeout":60000,"rpId":"example.com","allowCredentials":[{"type":"public-key","id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","transports":["internal"]}],"userVerification":"preferred","hints":["security-key"],"extensions":{"credProps":"true"}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeCredentialRequestOptionsIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(CredentialRequestOptions.class));
    }

    @Test
    void typeCredentialRequestOptionsIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(CredentialRequestOptions.class)));
    }

    @Test
    void typeCredentialRequestOptionsIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(CredentialRequestOptions.class)));
    }

    @Test
    void credentialRequestOptionsJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void credentialRequestOptionsJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(CredentialRequestOptions.class)));
    }

    @Test
    void credentialRequestOptionsSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "timeout",
        "rpId",
        "allowCredentials",
        "userVerification",
        "hints",
        "extensions"
    })
    void typeCredentialRequestOptionsFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"challenge"})
    void typeCredentialRequestOptionsFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"challenge"})
    void typeCredentialRequestOptionsFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }
}
