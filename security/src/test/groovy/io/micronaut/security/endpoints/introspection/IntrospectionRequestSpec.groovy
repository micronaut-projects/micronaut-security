package io.micronaut.security.endpoints.introspection

import io.micronaut.context.annotation.Requires
import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.*
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.serde.SerdeIntrospections
import spock.lang.Shared

import jakarta.validation.Valid
import jakarta.validation.Validator

class IntrospectionRequestSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        "IntrospectionRequestSpec"
    }

    @Shared
    Validator validator = applicationContext.getBean(Validator)

    void "IntrospectionRequest is annotated with @Serdeable.Deserializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getDeserializableIntrospection(Argument.of(IntrospectionRequest))

        then:
        noExceptionThrown()
    }

    void "IntrospectionRequest is annotated with @Serdeable.Serializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getSerializableIntrospection(Argument.of(IntrospectionRequest))

        then:
        noExceptionThrown()
    }

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
        IntrospectionRequest req = new IntrospectionRequest(null, null)

        then:
        !validator.validate(req).isEmpty()
    }

    void "IntrospectionRequest::tokenTypeHint is optional"() {
        when:
        IntrospectionRequest req = validIntrospectionRequest()

        then:
        validator.validate(req).isEmpty()
    }

    static IntrospectionRequest validIntrospectionRequest() {
        new IntrospectionRequest("2YotnFZFEjr1zCsicMWpAA", null)
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
