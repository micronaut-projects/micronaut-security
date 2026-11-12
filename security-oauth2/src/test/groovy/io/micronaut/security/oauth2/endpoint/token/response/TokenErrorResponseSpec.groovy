package io.micronaut.security.oauth2.endpoint.token.response

import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant
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
}
