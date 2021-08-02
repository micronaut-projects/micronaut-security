package io.micronaut.security.endpoints.introspection

import io.micronaut.context.annotation.Requires
import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Consumes
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.Produces
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.annotation.Secured
import io.micronaut.security.endpoints.introspection.IntrospectionRequest
import io.micronaut.security.rules.SecurityRule
import spock.lang.Shared

import javax.validation.Valid
import javax.validation.Validator

class IntrospectionRequestSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        "IntrospectionRequestSpec"
    }

    @Shared
    Validator validator = applicationContext.getBean(Validator)

    void "IntrospectionRequest is annotated with Introspected"() {
        when:
        BeanIntrospection.getIntrospection(IntrospectionRequest.class);

        then:
        noExceptionThrown()
    }

    void "valid IntrospectionRequest does not trigger any constraint exception"() {
        when:
        IntrospectionRequest req = validIntrospectionRequest()

        then:
        validator.validate(req).isEmpty()
    }

    void "IntrospectionRequest::token is required"() {
        when:
        IntrospectionRequest req = validIntrospectionRequest()
        req.token = null

        then:
        !validator.validate(req).isEmpty()
    }

    void "IntrospectionRequest::tokenTypeHint is optional"() {
        when:
        IntrospectionRequest req = validIntrospectionRequest()
        req.tokenTypeHint = null

        then:
        validator.validate(req).isEmpty()
    }

    static IntrospectionRequest validIntrospectionRequest() {
        IntrospectionRequest req = new IntrospectionRequest()
        req.token = "2YotnFZFEjr1zCsicMWpAA"
        req
    }

    void "token type hint needs to be supplied as a string separated with underscores"() {
        when:
        String response = client.retrieve(HttpRequest.POST('/introspection/echo', new IntrospectionRequest("2YotnFZFEjr1zCsicMWpAA", "access_token")).contentType(MediaType.APPLICATION_FORM_URLENCODED))

        then:
        'access_token' == response
    }

    @Requires(property = 'spec.name', value = 'IntrospectionRequestSpec')
    @Controller("/introspection/echo")
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class MockIntrospectionRequestEchoController {

        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces(MediaType.TEXT_PLAIN)
        @Post
        String echo(@Body @Valid IntrospectionRequest introspectionRequest) {
            introspectionRequest.tokenTypeHint
        }
    }
}
