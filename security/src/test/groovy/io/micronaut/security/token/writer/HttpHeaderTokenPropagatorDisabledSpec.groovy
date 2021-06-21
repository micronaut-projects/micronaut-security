package io.micronaut.security.token.writer

import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.token.propagation.HttpHeaderTokenPropagator

class HttpHeaderTokenPropagatorDisabledSpec extends ApplicationContextSpecification {

    void "HttpHeaderTokenPropagator is enabled by default"() {
        when:
        applicationContext.getBean(HttpHeaderTokenPropagator)

        then:
        noExceptionThrown()
    }
}
