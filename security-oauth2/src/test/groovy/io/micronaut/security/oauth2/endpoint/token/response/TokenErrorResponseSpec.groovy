package io.micronaut.security.oauth2.endpoint.token.response

import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import spock.lang.Specification

class TokenErrorResponseSpec extends Specification {
    void snakeCaseStrategyIsUsed() {
        given:
        JsonMapper jsonMapper = JsonMapper.createDefault()
        TokenErrorResponse obj = new TokenErrorResponse()
        obj.error = TokenError.INVALID_CLIENT
        obj.errorUri = "errorUri"
        obj.errorDescription = "errorDescription"

        when:
        JsonNode jsonNode = jsonMapper.writeValueToTree(obj)
        then:
        jsonNode.isObject()
        3 == jsonNode.size()
        "invalid_client" == jsonNode.get("error").getStringValue()
        "errorUri" == jsonNode.get("error_uri").getStringValue()
        "errorDescription" == jsonNode.get("error_description").getStringValue()
    }

    void "raw error code is serialized under error"() {
        given:
        JsonMapper jsonMapper = JsonMapper.createDefault()
        TokenErrorResponse obj = new TokenErrorResponse()
        obj.errorCode = "some_vendor_code"

        when:
        JsonNode jsonNode = jsonMapper.writeValueToTree(obj)

        then:
        jsonNode.isObject()
        1 == jsonNode.size()
        "some_vendor_code" == jsonNode.get("error").getStringValue()
        obj.error == TokenError.UNKNOWN
    }

    void "error=#code deserializes to #expected keeping the raw code"(String code, TokenError expected) {
        given:
        JsonMapper jsonMapper = JsonMapper.createDefault()
        String json = '{"error":"' + code + '","error_description":"desc","error_uri":"https://example.com/errors"}'

        when:
        TokenErrorResponse response = jsonMapper.readValue(json, TokenErrorResponse)

        then:
        response.error == expected
        response.errorCode == code
        response.errorDescription == "desc"
        response.errorUri == "https://example.com/errors"
        response.toString() == "error: " + code + ", errorDescription: desc, errorUri: https://example.com/errors"

        where:
        code                      | expected
        'invalid_grant'           | TokenError.INVALID_GRANT
        'invalid_token'           | TokenError.INVALID_TOKEN
        'temporarily_unavailable' | TokenError.TEMPORARILY_UNAVAILABLE
        'slow_down'               | TokenError.SLOW_DOWN
        'some_vendor_code'        | TokenError.UNKNOWN
    }

    void "a body without error does not fail to deserialize and toString is null safe"() {
        given:
        JsonMapper jsonMapper = JsonMapper.createDefault()

        when:
        TokenErrorResponse response = jsonMapper.readValue('{"error_description":"desc"}', TokenErrorResponse)

        then:
        response.error == null
        response.errorCode == null
        response.errorDescription == "desc"
        response.toString() == "error: null, errorDescription: desc, errorUri: null"

        when:
        String s = new TokenErrorResponse().toString()

        then:
        noExceptionThrown()
        s == "error: null, errorDescription: null, errorUri: null"
    }

    void "setError keeps the raw error code in sync"() {
        given:
        TokenErrorResponse response = new TokenErrorResponse()

        when:
        response.error = TokenError.SERVER_ERROR

        then:
        response.errorCode == "server_error"

        when:
        response.error = null

        then:
        response.errorCode == null
        response.error == null
    }
}
