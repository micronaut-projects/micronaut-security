package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.security.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class CookieEnabledSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        Map<String, Object> conf = super.configuration + [
            'micronaut.security.token.jwt.cookie.enabled': false,
        ]
        conf
    }

    @Unroll("if micronaut.security.token.jwt.cookie.enabled=false bean [#description] is not loaded")
    void "if micronaut.security.token.jwt.cookie.enabled=false security related beans are not loaded"(Class clazz, String description) {
        when:
        applicationContext.getBean(clazz)

        then:
        def e = thrown(NoSuchBeanException)
        e.message.contains('No bean of type ['+clazz.name+'] exists.')

        where:
        clazz << [
                AccessTokenCookieConfiguration,
                JwtCookieConfigurationProperties,
                JwtCookieTokenReader,
        ]

        description = clazz.name
    }
}
