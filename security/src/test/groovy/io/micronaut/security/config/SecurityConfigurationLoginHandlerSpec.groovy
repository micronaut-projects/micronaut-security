package io.micronaut.security.config

import io.micronaut.context.ApplicationContext
import io.micronaut.security.config.SecurityConfiguration
import io.micronaut.security.handlers.LoginHandlerMode
import spock.lang.Specification
import spock.lang.Unroll

class SecurityConfigurationLoginHandlerSpec extends Specification {

    void "by default no login handler mode is set"() {
        when:
        ApplicationContext applicationContext = ApplicationContext.run([:])

        then:
        applicationContext.containsBean(SecurityConfiguration)
        !applicationContext.getBean(SecurityConfiguration).getLoginHandler()

        cleanup:
        applicationContext.close()
    }

    @Unroll
    void "if property micronaut.security.login-handler = #mode io.micronaut.security.config.SecurityConfiguration#getLoginHandler = #mode"(LoginHandlerMode mode) {
        when:
        ApplicationContext applicationContext = ApplicationContext.run(['micronaut.security.login-handler': mode.toString()])

        then:
        applicationContext.containsBean(SecurityConfiguration)
        applicationContext.getBean(SecurityConfiguration).getLoginHandler() == mode

        cleanup:
        applicationContext.close()

        where:
        mode << [LoginHandlerMode.SESSION, LoginHandlerMode.COOKIE, LoginHandlerMode.BEARER]

    }
}
