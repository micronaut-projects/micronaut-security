package io.micronaut.security.token.jwt.render

import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.core.type.Argument
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.serde.ObjectMapper
import io.micronaut.serde.SerdeIntrospections

class AccessRefreshTokenSpec extends ApplicationContextSpecification {
    def "token json matches OAuth 2.0 RFC6749 specification"(){
        given: "we have an jackson mapper that will give us consistent results"
        ObjectMapper mapper = ObjectMapper.getDefault()

        and : "a fully populated token"
            AccessRefreshToken token = new AccessRefreshToken("1234", "abcd", "Bearer", null)

        when: "we serialize the object to json"
            def rawJsonString = mapper.writeValueAsString(token)

        then: "we will get an OAuth 2.0 RFC6749 compliant value"
            rawJsonString == "{\"access_token\":\"1234\",\"refresh_token\":\"abcd\",\"token_type\":\"Bearer\"}"
    }

    void "AccessRefreshToken  is annotated with @Introspected"() {
        when:
        BeanIntrospection.getIntrospection(AccessRefreshToken)

        then:
        noExceptionThrown()
    }

    void "AccessRefreshToken is annotated with @Serdeable.Deserializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getDeserializableIntrospection(Argument.of(AccessRefreshToken))

        then:
        noExceptionThrown()
    }

    void "AccessRefreshToken is annotated with @Serdeable.Serializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getSerializableIntrospection(Argument.of(AccessRefreshToken))

        then:
        noExceptionThrown()
    }
}
