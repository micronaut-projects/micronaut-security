package io.micronaut.security.endpoints.introspection

import io.micronaut.context.annotation.Requires
import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.core.type.Argument
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.serde.ObjectMapper
import io.micronaut.serde.SerdeIntrospections
import spock.lang.Issue
import spock.lang.Shared

import jakarta.validation.Validator

class IntrospectionResponseSpec extends EmbeddedServerSpecification {

    @Shared
    Validator validator = applicationContext.getBean(Validator)

    @Override
    String getSpecName() {
        'IntrospectionResponseSpec'
    }

    void "IntrospectionResponse is annotated with @Serdeable.Deserializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getDeserializableIntrospection(Argument.of(IntrospectionResponse))

        then:
        noExceptionThrown()
    }

    void "IntrospectionResponse is annotated with @Serdeable.Serializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getSerializableIntrospection(Argument.of(IntrospectionResponse))

        then:
        noExceptionThrown()
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

        then:
        rsp.scope == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::clientId is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        rsp.clientId == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::username is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        rsp.username == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::tokenType is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        rsp.tokenType == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::exp is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        rsp.exp == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::iat is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        rsp.iat == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::nbf is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        rsp.nbf == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::sub is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        rsp.sub == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::aud is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        rsp.aud == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::iss is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()


        then:
        rsp.iss == null
        validator.validate(rsp).isEmpty()
    }

    void "IntrospectionResponse::jti is optional"() {
        when:
        IntrospectionResponse rsp = validIntrospectionResponse()

        then:
        validator.validate(rsp).isEmpty()
    }

    static IntrospectionResponse validIntrospectionResponse() {
        new IntrospectionResponse(true,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null)
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
    void "test anyGetter with ObjectMapper registered in application context"() {
        given:
        ObjectMapper objectMapper = applicationContext.getBean(ObjectMapper)

        IntrospectionResponse response = new IntrospectionResponse(true,
                "access_token",
                "read write dolphin",
                "l238j323ds-23ij4",
                "jdoe",
                1419356238,
                1419350238,
                null,
                "Z5O3upPC88QrAjx00dis",
                "https://protected.example.net/resource",
                "https://server.example.com/",
                null,
                ["extension_field": "twenty-seven"])

        when:
        String str = objectMapper.writeValueAsString(response)

        then:
        str.contains('extension_field')
    }

    void "test anyGetter with instantiated ObjectMapper"() {
        given:
        ObjectMapper objectMapper = ObjectMapper.getDefault()

        IntrospectionResponse response = new IntrospectionResponse(true,
                "access_token",
                "read write dolphin",
                "l238j323ds-23ij4",
                "jdoe",
                1419356238,
                1419350238,
                null,
                "Z5O3upPC88QrAjx00dis",
                "https://protected.example.net/resource",
                "https://server.example.com/",
                null,
                ["extension_field": "twenty-seven"])

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
