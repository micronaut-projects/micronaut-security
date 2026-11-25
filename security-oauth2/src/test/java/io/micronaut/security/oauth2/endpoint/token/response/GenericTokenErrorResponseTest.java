package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.json.JsonMapper;
import io.micronaut.json.tree.JsonNode;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GenericTokenErrorResponseTest {

    private static final JsonMapper JSON_MAPPER = JsonMapper.createDefault();

    @Test
    void isIntrospected() {
        BeanIntrospection<GenericTokenErrorResponse> introspection = BeanIntrospection.getIntrospection(GenericTokenErrorResponse.class);

        assertEquals(3, introspection.getBeanProperties().size());
        assertTrue(introspection.getProperty("error").isPresent());
        assertTrue(introspection.getProperty("errorDescription").isPresent());
        assertTrue(introspection.getProperty("errorUri").isPresent());

        GenericTokenErrorResponse response = introspection.instantiate("invalid_grant", "Bad credentials", "https://example.com/errors");
        assertEquals("invalid_grant", response.error());
        assertEquals("Bad credentials", response.errorDescription());
        assertEquals("https://example.com/errors", response.errorUri());
    }

    @Test
    void serializesWithSnakeCase() throws IOException {
        GenericTokenErrorResponse response = new GenericTokenErrorResponse("invalid_client", "Client authentication failed", "https://example.com/errors");

        JsonNode json = JSON_MAPPER.writeValueToTree(response);

        assertTrue(json.isObject());
        assertEquals(3, json.size());
        assertEquals("invalid_client", json.get("error").getStringValue());
        assertEquals("Client authentication failed", json.get("error_description").getStringValue());
        assertEquals("https://example.com/errors", json.get("error_uri").getStringValue());
    }

    @Test
    void deserializesTheErrorCodesOfRfc6749() throws IOException {
        String body = "{\"error\":\"invalid_grant\",\"error_description\":\"Bad credentials\",\"error_uri\":\"https://example.com/errors\"}";

        GenericTokenErrorResponse response = JSON_MAPPER.readValue(body, GenericTokenErrorResponse.class);

        assertEquals(TokenError.INVALID_GRANT.toString(), response.error());
        assertEquals("Bad credentials", response.errorDescription());
        assertEquals("https://example.com/errors", response.errorUri());
    }

    @Test
    void deserializesErrorCodesOutsideRfc6749() throws IOException {
        String body = "{\"error\":\"account_locked\",\"error_description\":\"The account is locked\"}";

        GenericTokenErrorResponse response = JSON_MAPPER.readValue(body, GenericTokenErrorResponse.class);

        assertEquals("account_locked", response.error());
        assertEquals("The account is locked", response.errorDescription());
        assertNull(response.errorUri());
    }

    @Test
    void ignoresMembersProvidersAddToTheErrorResponse() throws IOException {
        String body = "{\"error\":\"interaction_required\",\"error_codes\":[50076],\"timestamp\":\"2026-11-06 10:00:00Z\",\"trace_id\":\"abc\"}";

        GenericTokenErrorResponse response = JSON_MAPPER.readValue(body, GenericTokenErrorResponse.class);

        assertEquals("interaction_required", response.error());
        assertNull(response.errorDescription());
        assertNull(response.errorUri());
    }
}
