package io.micronaut.security.oauth2.client

import io.micronaut.core.annotation.ReflectiveAccess
import spock.lang.Specification

class DefaultOpenIdProviderMetadataSpec extends Specification {
    void "DefaultOpenIdProviderMetadata is annotated with ReflectiveAccess"() {
        expect:
        DefaultOpenIdProviderMetadata.class.isAnnotationPresent(ReflectiveAccess)
    }
}
