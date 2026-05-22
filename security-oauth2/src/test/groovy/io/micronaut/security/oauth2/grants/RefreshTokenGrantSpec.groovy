package io.micronaut.security.oauth2.grants

import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import spock.lang.Specification

class RefreshTokenGrantSpec extends Specification {
    void snakeCaseStrategyIsUsed() {
        given:
        JsonMapper jsonMapper = JsonMapper.createDefault()

        RefreshTokenGrant obj = new RefreshTokenGrant()
        obj.scope = "scope"
        obj.refreshToken = "refreshToken"

        when:
        JsonNode jsonNode = jsonMapper.writeValueToTree(obj)
        then:
        jsonNode.isObject()
        3 == jsonNode.size()
        "scope" == jsonNode.get("scope").getStringValue()
        "refreshToken" == jsonNode.get("refresh_token").getStringValue()
        "refresh_token" == jsonNode.get("grant_type").getStringValue()
    }
}
