package io.micronaut.security.oauth2.grants

import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import spock.lang.Specification

class AuthorizationCodeGrantSpec extends Specification {
    void snakeCaseStrategyIsUsed() {
        given:
        JsonMapper jsonMapper = JsonMapper.createDefault()
        AuthorizationCodeGrant obj = new AuthorizationCodeGrant()
        obj.codeVerifier = "codeVerifier"
        obj.redirectUri = "redirectUri"
        obj.code = "code"

        when:
        JsonNode jsonNode = jsonMapper.writeValueToTree(obj)
        then:
        jsonNode.isObject()
        4 == jsonNode.size()
        "code" == jsonNode.get("code").getStringValue()
        "redirectUri" == jsonNode.get("redirect_uri").getStringValue()
        "codeVerifier" == jsonNode.get("code_verifier").getStringValue()
        "authorization_code" == jsonNode.get("grant_type").getStringValue()
    }

    void "AuthorizationCodeGrant is annotated with Introspected"() {
        when:
        BeanIntrospection.getIntrospection(AuthorizationCodeGrant.class);

        then:
        noExceptionThrown()
    }

    void "AuthorizationCodeGrant::toMap"() {
        given:
        AuthorizationCodeGrant grant = new AuthorizationCodeGrant();
        grant.setCode("xxx");
        grant.setGrantType(GrantType.AUTHORIZATION_CODE.toString());

        expect:
        ['code': 'xxx', 'grant_type': 'authorization_code'] == grant.toMap()
    }
}
