package io.micronaut.security.oauth2.endpoint.denied

import io.micronaut.context.ApplicationContext
import io.micronaut.security.oauth2.endpoints.DeniedController
import spock.lang.Specification

class DeniedControllerEnabledSpec extends Specification {

    void "DeniedController is enabled by default"() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.enabled': true,
        ])

        expect:
        applicationContext.containsBean(DeniedController)

        cleanup:
        applicationContext.close()
    }

    void "DeniedController can be disabled with "() {
        given:
        ApplicationContext applicationContext = ApplicationContext.run([
                'micronaut.security.enabled': true,
                'micronaut.security.oauth2.enabled': true,
                'micronaut.security.endpoints.denied.enabled': false
        ])

        expect:
        !applicationContext.containsBean(DeniedController)

        cleanup:
        applicationContext.close()
    }
}
