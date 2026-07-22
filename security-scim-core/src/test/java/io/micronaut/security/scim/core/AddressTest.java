package io.micronaut.security.scim.core;

import io.micronaut.context.BeanContext;
import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.type.Argument;
import io.micronaut.json.JsonMapper;
import io.micronaut.serde.SerdeIntrospections;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class AddressTest {
    @Inject
    BeanContext beanContext;

    @Inject
    Validator validator;

    @Inject
    JsonMapper jsonMapper;

    @Test
    void everyFieldInAddressIsOptional() {
        Address address = new Address(null, null, null, null, null, null, null, null);
        Set<ConstraintViolation<Address>> violations = validator.validate(address);
        assertTrue(violations.isEmpty());
    }

    @Test
    void isDeserializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getDeserializableIntrospection(Argument.of(Address.class)));
    }

    @Test
    void isSerializable() {
        SerdeIntrospections introspections = assertDoesNotThrow(() -> beanContext.getBean(SerdeIntrospections.class));
        assertDoesNotThrow(() -> introspections.getSerializableIntrospection(Argument.of(Address.class)));
    }

    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(Address.class));
    }

    @Test
    void addressDeserialization() throws IOException {
        String json = """
            {
                  "type": "work",
                  "streetAddress": "100 Universal City Plaza",
                  "locality": "Hollywood",
                  "region": "CA",
                  "postalCode": "91608",
                  "country": "USA",
                  "formatted": "100 Universal City Plaza\\nHollywood, CA 91608 USA",
                  "primary": true
                }""";

        Address address = jsonMapper.readValue(json, Address.class);
        assertEquals("work", address.type());
        assertEquals("100 Universal City Plaza", address.streetAddress());
        assertEquals("Hollywood", address.locality());
        assertEquals("CA", address.region());
        assertEquals("91608", address.postalCode());
        assertEquals("USA", address.country());
        assertEquals("100 Universal City Plaza\nHollywood, CA 91608 USA", address.formatted());
        assertNotNull(address.primary());
        assertTrue(address.primary());
    }

    @Test
    void deserializesCaseInsensitiveStringPrimaryValue() throws IOException {
        Address address = jsonMapper.readValue("""
            {
              "type": "work",
              "primary": "True"
            }
            """, Address.class);

        assertEquals(true, address.primary());
    }
}
