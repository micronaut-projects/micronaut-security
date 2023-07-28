package io.micronaut.security.oauth2.grants

import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import spock.lang.Specification

class SamlBearerAssertionGrantSpec extends Specification {

    void snakeCaseStrategyIsUsed() {
        given:
        JsonMapper jsonMapper = JsonMapper.createDefault()

        SamlBearerAssertionGrant obj = new SamlBearerAssertionGrant()
        obj.scope = "scope"
        obj.assertion = "assertion"

        when:
        JsonNode jsonNode = jsonMapper.writeValueToTree(obj)
        then:
        jsonNode.isObject()
        3 == jsonNode.size()
        "scope" == jsonNode.get("scope").getStringValue()
        "assertion" == jsonNode.get("assertion").getStringValue()
        "urn:ietf:params:oauth:grant-type:saml2-bearer" == jsonNode.get("grant_type").getStringValue()
    }
}
