package io.micronaut.security.token.jwt.validator

import io.micronaut.context.ApplicationContext
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class AuthenticationWithJwtGeneratorSpec extends Specification {

    @AutoCleanup
    @Shared
    ApplicationContext applicationContext = ApplicationContext.run()

    void "AuthenticationWithJwtGenerator bean exists"() {
        expect:
        applicationContext.containsBean(DefaultJwtAuthenticationFactory)
        applicationContext.containsBean(JwtAuthenticationFactory)
    }
}
