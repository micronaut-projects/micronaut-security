package io.micronaut.security.oauth2.endpoint.token.response

import com.fasterxml.jackson.databind.ObjectMapper
import groovy.json.JsonSlurper
import groovy.time.TimeCategory
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


    void "There is a constructor in TokenResponse for required fields"() {
        when:
        TokenResponse tokenResponse = new TokenResponse("MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3", 'bearer')

        then:
        tokenResponse.accessToken == "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3"
        tokenResponse.tokenType == 'bearer'
    }

    void "TokenResponse implements equals and hash code"() {
        given:
        TokenResponse respOne = new TokenResponse()
        respOne.with {
            accessToken = "2YotnFZFEjr1zCsicMWpAA"
            tokenType = "example"
            expiresIn = 3600
            refreshToken = "tGzv3JOkF0XG5Qx2TlKWIA"
        }

        TokenResponse respTwo = new TokenResponse()
        respTwo.with {
            accessToken = "2YotnFZFEjr1zCsicMWpAA"
            tokenType = "example"
            expiresIn = 3600
            refreshToken = "tGzv3JOkF0XG5Qx2TlKWIA"
        }

        expect:
        respOne == respTwo
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

    void "TokenResponse::getExpiration uses expiresIn"() {
        when:
        TokenResponse tokenResponse = new TokenResponse()

        then:
        !tokenResponse.getExpiresInDate().isPresent()

        when:
        tokenResponse.expiresIn = 3600

        then:
        tokenResponse.getExpiresInDate().isPresent()

        when:
        Date halfAnHour = new Date()
        use(TimeCategory) {
            halfAnHour += 30.minutes
        }

        then:
        tokenResponse.getExpiresInDate().get().after(halfAnHour)

        when:
        Date twoHours = new Date()
        use(TimeCategory) {
            twoHours += 2.hours
        }

        then:
        tokenResponse.getExpiresInDate().get().before(twoHours)
    }
}
