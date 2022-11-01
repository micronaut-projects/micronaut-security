package io.micronaut.security.token.jwt.render

import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.core.type.Argument
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.serde.ObjectMapper
import io.micronaut.serde.SerdeIntrospections
import static net.javacrumbs.jsonunit.JsonAssert.assertJsonEquals;

class BearerAccessRefreshTokenSpec extends ApplicationContextSpecification {
    def "token json matches OAuth 2.0 RFC6749 specification"(){
        given: "we have an jackson mapper that will give us consistent results"
        ObjectMapper mapper = ObjectMapper.getDefault()

        and : "a fully populated bearer token"
        BearerAccessRefreshToken token = new BearerAccessRefreshToken("testing", ["admin", "superuser"], 3600, "1234", "abcd", "Bearer")

        when: "we serialize the object to json"
        String rawJsonString = mapper.writeValueAsString(token)

        then: "we will get an OAuth 2.0 RFC6749 compliant value"
        assertJsonEquals(rawJsonString, "{\"access_token\":\"1234\",\"expires_in\":3600,\"refresh_token\":\"abcd\",\"roles\":[\"admin\",\"superuser\"],\"token_type\":\"Bearer\",\"username\":\"testing\"}")
    }

    void "BearerAccessRefreshToken  is annotated with @Introspected"() {
        when:
        BeanIntrospection.getIntrospection(BearerAccessRefreshToken)

        then:
        noExceptionThrown()
    }

    void "BearerAccessRefreshToken is annotated with @Serdeable.Deserializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getDeserializableIntrospection(Argument.of(BearerAccessRefreshToken))

        then:
        noExceptionThrown()
    }

    void "BearerAccessRefreshToken is annotated with @Serdeable.Serializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getSerializableIntrospection(Argument.of(BearerAccessRefreshToken))

        then:
        noExceptionThrown()
    }
}
