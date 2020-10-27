package io.micronaut.security.oauth2.endpoint.token.response

import com.fasterxml.jackson.databind.ObjectMapper
import groovy.json.JsonSlurper
import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.security.oauth2.ApplicationContextSpecification
import spock.lang.Shared

class TokenResponseSpec extends ApplicationContextSpecification {

    @Shared
    ObjectMapper objectMapper = applicationContext.getBean(ObjectMapper)

    void "TokenResponse is annotated with Introspected"() {
        when:
        BeanIntrospection.getIntrospection(TokenResponse)

        then:
        noExceptionThrown()
    }

    void "TokenResponse uses snake case for its fields"() {
        when:
        TokenResponse tokenResponse = new TokenResponse()
        tokenResponse.accessToken = "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3"
        tokenResponse.tokenType = 'bearer'
        tokenResponse.expiresIn = 3600
        tokenResponse.refreshToken = "IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk"
        tokenResponse.scope = "create"
        String json = objectMapper.writeValueAsString(tokenResponse)
        def m = new JsonSlurper().parseText(json)

        then:
        m["access_token"] == "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3"
        m["token_type"] == "bearer"
        m["expires_in"] == 3600
        m["refresh_token"] == "IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk"
        m["scope"] == "create"
    }
}
