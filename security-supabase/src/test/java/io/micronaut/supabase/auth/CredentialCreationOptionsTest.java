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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link CredentialCreationOptions}.
 */
@MicronautTest(startApplication = false)
class CredentialCreationOptionsTest {

    private static final CredentialCreationOptions SAMPLE = new CredentialCreationOptions(
        new CredentialCreationOptions.Rp("example.com", "Example App"),
        new CredentialCreationOptions.User("8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", "alice@example.com", "Alice"),
        "Y2hhbGxlbmdl",
        List.of(new CredentialCreationOptions.PubKeyCredParam("public-key", -7)),
        60000,
        List.of(new PublicKeyCredentialDescriptor("public-key", "8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c", List.of("internal"))),
        new CredentialCreationOptions.AuthenticatorSelection(
            "platform",
            true,
            "preferred",
            "preferred"
        ),
        "none",
        List.of("packed"),
        List.of("security-key"),
        Map.of("credProps", "true")
    );

    private static final String JSON = """
        {"rp":{"id":"example.com","name":"Example App"},"user":{"id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","name":"alice@example.com","displayName":"Alice"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":60000,"excludeCredentials":[{"type":"public-key","id":"8f7c1a3e-6d2b-4e9a-9c1d-2b3f4a5e6d7c","transports":["internal"]}],"authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":true,"residentKey":"preferred","userVerification":"preferred"},"attestation":"none","attestationFormats":["packed"],"hints":["security-key"],"extensions":{"credProps":"true"}}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeCredentialCreationOptionsIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(CredentialCreationOptions.class));
    }

    @Test
    void typeCredentialCreationOptionsIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(CredentialCreationOptions.class)));
    }

    @Test
    void typeCredentialCreationOptionsIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(CredentialCreationOptions.class)));
    }

    @Test
    void credentialCreationOptionsJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void credentialCreationOptionsJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(CredentialCreationOptions.class)));
    }

    @Test
    void credentialCreationOptionsSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "timeout",
        "excludeCredentials",
        "authenticatorSelection",
        "attestation",
        "attestationFormats",
        "hints",
        "extensions"
    })
    void typeCredentialCreationOptionsFieldCanBeNull(String property) {
        assertTrue(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"rp", "user", "challenge", "pubKeyCredParams"})
    void typeCredentialCreationOptionsFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"challenge"})
    void typeCredentialCreationOptionsFieldCannotBeBlank(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, "")).isEmpty(), property);
        assertFalse(validator.validate(Records.with(SAMPLE, property, "   ")).isEmpty(), property);
    }

    @ParameterizedTest
    @ValueSource(strings = {"pubKeyCredParams"})
    void typeCredentialCreationOptionsFieldCannotBeEmpty(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, List.of())).isEmpty(), property);
    }
}
