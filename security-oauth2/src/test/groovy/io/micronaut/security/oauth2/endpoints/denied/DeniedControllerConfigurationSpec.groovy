package io.micronaut.security.oauth2.endpoints.denied

import io.micronaut.context.ApplicationContext
import io.micronaut.security.oauth2.endpoints.DeniedControllerConfiguration
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class DeniedControllerConfigurationSpec extends Specification {

    @AutoCleanup
    @Shared
    ApplicationContext applicationContext = ApplicationContext.run()

    def "DeniedControllerConfiguration exists"() {
        applicationContext.containsBean(DeniedControllerConfiguration)
    }
}
