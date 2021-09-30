package io.micronaut.security.filters

import io.micronaut.context.ApplicationContext
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class SecurityFilterSpec extends Specification {
    @AutoCleanup
    @Shared
    ApplicationContext applicationContext = ApplicationContext.run()

    void "bean of type SecurityFilter exists even if management dependency is not present"() {
        expect:
        applicationContext.containsBean(SecurityFilter)
    }
}
