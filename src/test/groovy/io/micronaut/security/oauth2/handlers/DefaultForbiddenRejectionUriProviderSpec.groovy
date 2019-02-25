package io.micronaut.security.oauth2.handlers

import io.micronaut.context.ApplicationContext
import io.micronaut.security.handlers.ForbiddenRejectionUriProvider
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class DefaultForbiddenRejectionUriProviderSpec extends Specification {

    @Shared
    Map<String, Object> conf = [
            'micronaut.security.enabled': true,
            'micronaut.security.oauth2.enabled': true,
            'micronaut.security.endpoints.denied': true
    ]

    @AutoCleanup
    @Shared
    ApplicationContext applicationContext = ApplicationContext.run(conf)

    def "DefaultForbiddenRejectionUriProvider bean exist"() {
        when:
        ForbiddenRejectionUriProvider uriProvider = applicationContext.getBean(ForbiddenRejectionUriProvider)

        then:
        noExceptionThrown()
        uriProvider instanceof DefaultForbiddenRejectionUriProvider

        and: 'defaults to /denied'
        uriProvider.getForbiddenRedirectUri(null).get() == '/denied'
    }

}
