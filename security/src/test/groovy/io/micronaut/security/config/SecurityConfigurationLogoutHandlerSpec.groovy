package io.micronaut.security.config

import io.micronaut.context.ApplicationContext
import io.micronaut.security.handlers.LogoutHandler
import io.micronaut.security.handlers.LogoutHandlerMode
import spock.lang.Specification
import spock.lang.Unroll

class SecurityConfigurationLogoutHandlerSpec extends Specification {

    void "by default no logout handler is set"() {
        when:
        ApplicationContext applicationContext = ApplicationContext.run([:])

        then:
        applicationContext.containsBean(SecurityConfiguration)
        !applicationContext.getBean(SecurityConfiguration).getLogoutHandler()

        cleanup:
        applicationContext.close()
    }

    @Unroll
    void "if property micronaut.security.logout-handler = #mode io.micronaut.security.config.SecurityConfiguration#getLogoutHandler = #mode"(LogoutHandlerMode mode) {
        when:
        ApplicationContext applicationContext = ApplicationContext.run(['micronaut.security.logout-handler': mode.toString()])

        then:
        applicationContext.containsBean(SecurityConfiguration)
        applicationContext.getBean(SecurityConfiguration).getLogoutHandler()

        cleanup:
        applicationContext.close()

        where:
        mode << [LogoutHandlerMode.SESSION, LogoutHandlerMode.COOKIE]

    }
}
