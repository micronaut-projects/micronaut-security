package io.micronaut.security.propagation

import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.security.ApplicationContextSpecification
import io.micronaut.security.token.propagation.TokenPropagationHttpClientFilter

class TokenPropagationHttpClientFilterDisabledSpec extends ApplicationContextSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.writer.header.enabled': true,
        ]
    }

    void "TokenPropagationHttpClientFilter is disabled by default"() {
        when:
        applicationContext.getBean(TokenPropagationHttpClientFilter)

        then:
        thrown(NoSuchBeanException)
    }
}
