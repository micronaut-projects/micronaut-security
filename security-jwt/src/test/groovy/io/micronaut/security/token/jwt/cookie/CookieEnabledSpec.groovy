package io.micronaut.security.token.jwt.cookie

import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.testutils.ApplicationContextSpecification
import spock.lang.Unroll

class CookieEnabledSpec extends ApplicationContextSpecification {
    @Override
    Map<String, Object> getConfiguration() {
        super.configuration +
                [
            'micronaut.security.token.jwt.cookie.enabled': false,

        ]
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
                JwtCookieClearerLogoutHandler,
                JwtCookieConfigurationProperties,
                JwtCookieLoginHandler,
                JwtCookieTokenReader,
        ]

        description = clazz.name
    }
}
