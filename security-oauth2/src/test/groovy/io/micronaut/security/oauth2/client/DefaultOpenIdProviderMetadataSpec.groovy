package io.micronaut.security.oauth2.client

import io.micronaut.core.annotation.ReflectiveAccess
import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.core.type.Argument
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.serde.SerdeIntrospections

class DefaultOpenIdProviderMetadataSpec extends ApplicationContextSpecification {
    void "DefaultOpenIdProviderMetadata is annotated with ReflectiveAccess"() {
        expect:
        DefaultOpenIdProviderMetadata.class.isAnnotationPresent(ReflectiveAccess)
    }

    void "DefaultOpenIdProviderMetadata is annotated with @Introspected"() {
        when:
        BeanIntrospection.getIntrospection(DefaultOpenIdProviderMetadata)

        then:
        noExceptionThrown()
    }

    void "DefaultOpenIdProviderMetadata is annotated with @Serdeable.Deserializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getDeserializableIntrospection(Argument.of(DefaultOpenIdProviderMetadata))

        then:
        noExceptionThrown()
    }

    void "DefaultOpenIdProviderMetadata is annotated with @Serdeable.Serializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getSerializableIntrospection(Argument.of(DefaultOpenIdProviderMetadata))

        then:
        noExceptionThrown()
    }
}
