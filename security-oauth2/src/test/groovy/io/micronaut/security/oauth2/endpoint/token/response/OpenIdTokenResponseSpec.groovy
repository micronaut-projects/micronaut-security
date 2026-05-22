package io.micronaut.security.oauth2.endpoint.token.response

import io.micronaut.core.annotation.ReflectiveAccess
import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant
import spock.lang.Specification

class OpenIdTokenResponseSpec extends Specification {
    void "OpenIdTokenResponse is annotated with ReflectiveAccess"() {
        expect:
        OpenIdTokenResponse.class.isAnnotationPresent(ReflectiveAccess)
    }

    void "TokenResponse uses snake case for its fields"() {
        given:
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse()
        tokenResponse.idToken = "idToken"
        tokenResponse.accessToken = "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3"
        tokenResponse.tokenType = 'bearer'
        tokenResponse.expiresIn = 3600
        tokenResponse.refreshToken = "IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk"
        tokenResponse.scope = "create"

        JsonMapper jsonMapper = JsonMapper.createDefault()

        when:
        JsonNode jsonNode = jsonMapper.writeValueToTree(tokenResponse)
        then:
        jsonNode.isObject()

        then:
        jsonNode.get("access_token").getStringValue() == "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3"
        jsonNode.get("token_type").getStringValue() == "bearer"
        jsonNode.get("expires_in").longValue == 3600L
        jsonNode.get("refresh_token").getStringValue() == "IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk"
        jsonNode.get("scope").getStringValue() == "create"
        jsonNode.get("id_token").getStringValue() == 'idToken'
    }

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
}
