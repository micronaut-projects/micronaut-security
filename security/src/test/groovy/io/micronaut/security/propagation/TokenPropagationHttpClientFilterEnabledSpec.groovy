package io.micronaut.security.propagation

import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.security.token.propagation.TokenPropagationHttpClientFilter

class TokenPropagationHttpClientFilterEnabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.writer.header.enabled': true,
                'micronaut.security.token.propagation.enabled': true,
                ]

    }
    void "TokenPropagationHttpClientFilter is enabled if you set micronaut.security.token.jwt.propagation.enabled"() {
        when:
        applicationContext.getBean(TokenPropagationHttpClientFilter)

        then:
        noExceptionThrown()
    }
}
