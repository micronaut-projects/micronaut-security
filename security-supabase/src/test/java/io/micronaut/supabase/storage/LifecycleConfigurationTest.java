package io.micronaut.supabase.storage;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.supabase.auth.Records;
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
 * Verifies introspection, Serde metadata, JSON mapping and validation constraints of {@link LifecycleConfiguration}.
 */
@MicronautTest(startApplication = false)
class LifecycleConfigurationTest {

    private static final LifecycleConfiguration SAMPLE = new LifecycleConfiguration(List.of(new LifecycleConfiguration.Rule("expire-old", "Enabled", Map.of(), new LifecycleConfiguration.NoncurrentVersionExpiration(30, 2))));

    private static final String JSON = """
        {"rules":[{"id":"expire-old","status":"Enabled","filter":{},"noncurrentVersionExpiration":{"noncurrentDays":30,"newerNoncurrentVersions":2}}]}""";

    @Inject
    SerdeIntrospections serdeIntrospections;

    @Inject
    JsonMapper jsonMapper;

    @Inject
    Validator validator;

    @Test
    void typeLifecycleConfigurationIsAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(LifecycleConfiguration.class));
    }

    @Test
    void typeLifecycleConfigurationIsSerializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getSerializableIntrospection(Argument.of(LifecycleConfiguration.class)));
    }

    @Test
    void typeLifecycleConfigurationIsDeserializable() {
        assertDoesNotThrow(() -> serdeIntrospections.getDeserializableIntrospection(Argument.of(LifecycleConfiguration.class)));
    }

    @Test
    void lifecycleConfigurationJsonSerialization() throws IOException {
        assertEquals(JSON, jsonMapper.writeValueAsString(SAMPLE));
    }

    @Test
    void lifecycleConfigurationJsonDeserialization() throws IOException {
        assertEquals(SAMPLE, jsonMapper.readValue(JSON, Argument.of(LifecycleConfiguration.class)));
    }

    @Test
    void lifecycleConfigurationSampleHasNoConstraintViolations() {
        assertTrue(validator.validate(SAMPLE).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"rules"})
    void typeLifecycleConfigurationFieldCannotBeNull(String property) {
        assertFalse(validator.validate(Records.with(SAMPLE, property, null)).isEmpty(), property);
    }

    @Test
    void rulesAreValidatedInCascade() {
        LifecycleConfiguration.NoncurrentVersionExpiration expiration = new LifecycleConfiguration.NoncurrentVersionExpiration(30, null);
        assertTrue(validator.validate(new LifecycleConfiguration(List.of(new LifecycleConfiguration.Rule(null, "Disabled", Map.of(), expiration)))).isEmpty());
        assertFalse(validator.validate(new LifecycleConfiguration(List.of(Records.with(new LifecycleConfiguration.Rule("x", "Enabled", Map.of(), expiration), "status", "")))).isEmpty());
        assertFalse(validator.validate(new LifecycleConfiguration(List.of(Records.with(new LifecycleConfiguration.Rule("x", "Enabled", Map.of(), expiration), "filter", null)))).isEmpty());
        assertFalse(validator.validate(new LifecycleConfiguration(List.of(Records.with(new LifecycleConfiguration.Rule("x", "Enabled", Map.of(), expiration), "noncurrentVersionExpiration", null)))).isEmpty());
        assertFalse(validator.validate(new LifecycleConfiguration(List.of(new LifecycleConfiguration.Rule("x", "Enabled", Map.of(), Records.with(expiration, "noncurrentDays", null))))).isEmpty());
    }
}
