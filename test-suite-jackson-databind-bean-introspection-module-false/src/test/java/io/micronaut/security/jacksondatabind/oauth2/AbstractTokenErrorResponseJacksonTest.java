package io.micronaut.security.jacksondatabind.oauth2;

import io.micronaut.json.JsonMapper;
import io.micronaut.json.tree.JsonNode;
import io.micronaut.security.oauth2.endpoint.token.response.TokenError;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

abstract class AbstractTokenErrorResponseJacksonTest {

    @Inject
    JsonMapper jsonMapper;

    @ParameterizedTest
    @CsvSource({
        "invalid_grant,INVALID_GRANT",
        "invalid_token,INVALID_TOKEN",
        "temporarily_unavailable,TEMPORARILY_UNAVAILABLE",
        "slow_down,SLOW_DOWN",
        "some_vendor_code,UNKNOWN"
    })
    void errorCodesDeserializeKeepingTheRawCode(String code, TokenError expected) throws IOException {
        String json = "{\"error\":\"" + code + "\",\"error_description\":\"desc\",\"error_uri\":\"https://example.com/errors\"}";

        TokenErrorResponse response = jsonMapper.readValue(json, TokenErrorResponse.class);

        assertEquals(expected, response.getError());
        assertEquals(code, response.getErrorCode());
        assertEquals("desc", response.getErrorDescription());
        assertEquals("https://example.com/errors", response.getErrorUri());
        assertEquals("error: " + code + ", errorDescription: desc, errorUri: https://example.com/errors", response.toString());
    }

    @Test
    void bodyWithoutErrorDeserializesAndToStringIsNullSafe() throws IOException {
        TokenErrorResponse response = jsonMapper.readValue("{\"error_description\":\"desc\"}", TokenErrorResponse.class);

        assertNull(response.getError());
        assertNull(response.getErrorCode());
        assertEquals("desc", response.getErrorDescription());
        assertDoesNotThrow(response::toString);
        assertEquals("error: null, errorDescription: desc, errorUri: null", response.toString());
    }

    @Test
    void tokenErrorDeserializesUnknownCodesToUnknown() throws IOException {
        assertEquals(TokenError.INVALID_TOKEN, jsonMapper.readValue("\"invalid_token\"", TokenError.class));
        assertEquals(TokenError.UNKNOWN, jsonMapper.readValue("\"some_vendor_code\"", TokenError.class));
        assertEquals("\"invalid_token\"", jsonMapper.writeValueAsString(TokenError.INVALID_TOKEN));
    }

    @Test
    void serializationUsesSnakeCaseAndTheRawErrorCode() throws IOException {
        TokenErrorResponse response = new TokenErrorResponse();
        response.setError(TokenError.INVALID_CLIENT);
        response.setErrorDescription("errorDescription");
        response.setErrorUri("errorUri");

        JsonNode jsonNode = jsonMapper.writeValueToTree(response);

        assertTrue(jsonNode.isObject());
        assertEquals(3, jsonNode.size());
        assertEquals("invalid_client", jsonNode.get("error").getStringValue());
        assertEquals("errorDescription", jsonNode.get("error_description").getStringValue());
        assertEquals("errorUri", jsonNode.get("error_uri").getStringValue());

        TokenErrorResponse vendor = new TokenErrorResponse();
        vendor.setErrorCode("some_vendor_code");
        JsonNode vendorNode = jsonMapper.writeValueToTree(vendor);
        assertEquals("some_vendor_code", vendorNode.get("error").getStringValue());
        assertEquals(TokenError.UNKNOWN, vendor.getError());
    }
}
