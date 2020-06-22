package io.micronaut.security.token.writer

import io.micronaut.security.ApplicationContextSpecification
import io.micronaut.security.token.propagation.HttpHeaderTokenPropagator

class HttpHeaderTokenPropagatorEnabledSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + ['micronaut.security.token.propagation.header.enabled': true,]
    }

    void "JwtHttpClientFilter is enabled if you set micronaut.security.token.jwt.propagation.enabled"() {
        when:
        applicationContext.getBean(HttpHeaderTokenPropagator)

        then:
        noExceptionThrown()
    }
}
