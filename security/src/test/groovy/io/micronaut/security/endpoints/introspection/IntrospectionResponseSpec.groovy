package io.micronaut.security.endpoints.introspection

import com.fasterxml.jackson.databind.ObjectMapper
import io.micronaut.context.annotation.Requires
import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import spock.lang.Ignore
import spock.lang.Issue
import spock.lang.PendingFeature
import spock.lang.Shared

import javax.validation.Validator

class IntrospectionResponseSpec extends EmbeddedServerSpecification {

    @Shared
    Validator validator = applicationContext.getBean(Validator)

    @Override
    String getSpecName() {
        'IntrospectionResponseSpec'
    }

    void "IntrospectionResponse is annotated with Introspected"() {
        when:
        BeanIntrospection.getIntrospection(IntrospectionResponse.class);

        then:
        noExceptionThrown()
    }

    void "valid IntrospectionResponse does not trigger any constraint exception"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::scope is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.scope = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::clientId is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.clientId = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::username is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.username = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::tokenType is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.tokenType = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::exp is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.exp = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::iat is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.iat = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::nbf is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.nbf = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::sub is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.sub = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::aud is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.aud = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::iss is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.iss = null

        then:
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::jti is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()
        rsp.jti = null

        then:
        validator.validate(rsp).isEmpty()
    }

    static IntrospectionResponse validIntrospectionResponse() {
        IntrospectionResponse req = new IntrospectionResponse()
        req.active = true
        req
    }

    void "verify fields are annotated with JsonProperty"() {
        when:
        IntrospectionResponse resp = client.retrieve('/introspection/response/echo', IntrospectionResponse)

        then:
        resp
        resp.active
        resp.clientId == "l238j323ds-23ij4"
        resp.tokenType == "access_token"
        resp.username == "jdoe"
        resp.scope == "read write dolphin"
        resp.sub == "Z5O3upPC88QrAjx00dis"
        resp.aud == "https://protected.example.net/resource"
        resp.iss == "https://server.example.com/"
        resp.exp == 1419356238
        resp.iat == 1419350238
    }

    @Issue("https://github.com/micronaut-projects/micronaut-core/issues/4179")
    @PendingFeature
    void "test anyGetter with ObjectMapper registered in application context"() {
        given:
        ObjectMapper objectMapper = applicationContext.getBean(ObjectMapper)

        IntrospectionResponse response = new IntrospectionResponse()
        response.active = true
        response.clientId = "l238j323ds-23ij4"
        response.tokenType = "access_token"
        response.username = "jdoe"
        response.scope = "read write dolphin"
        response.sub = "Z5O3upPC88QrAjx00dis"
        response.aud = "https://protected.example.net/resource"
        response.iss = "https://server.example.com/"
        response.exp = 1419356238
        response.iat = 1419350238
        response.extensions = ["extension_field": "twenty-seven"]

        when:
        String str = objectMapper.writeValueAsString(response)

        then:
        str.contains('extension_field')
    }

    void "test anyGetter with instantiated ObjectMapper"() {
        given:
        ObjectMapper objectMapper = new ObjectMapper()

        IntrospectionResponse response = new IntrospectionResponse()
        response.active = true
        response.clientId = "l238j323ds-23ij4"
        response.tokenType = "access_token"
        response.username = "jdoe"
        response.scope = "read write dolphin"
        response.sub = "Z5O3upPC88QrAjx00dis"
        response.aud = "https://protected.example.net/resource"
        response.iss = "https://server.example.com/"
        response.exp = 1419356238
        response.iat = 1419350238
        response.extensions = ["extension_field": "twenty-seven"]

        when:
        String str = objectMapper.writeValueAsString(response)

        then:
        str.contains('extension_field')
    }

    @Requires(property = "spec.name", value = "IntrospectionResponseSpec")
    @Controller("/introspection/response/echo")
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class IntrospectionResponseEchoController {

        @Get
        Map<String, Object> index() {
            [
                "active": true,
                "client_id": "l238j323ds-23ij4",
                "token_type": "access_token",
                "username": "jdoe",
                "scope": "read write dolphin",
                "sub": "Z5O3upPC88QrAjx00dis",
                "aud": "https://protected.example.net/resource",
                "iss": "https://server.example.com/",
                "exp": 1419356238,
                "iat": 1419350238,
                "extension_field": "twenty-seven"
            ] as Map<String, Object>
        }
    }
}
