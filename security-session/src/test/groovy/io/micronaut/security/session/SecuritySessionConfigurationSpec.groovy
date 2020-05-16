package io.micronaut.security.session

import io.micronaut.security.ApplicationContextSpecification
import spock.lang.Shared
import spock.lang.Subject

class SecuritySessionConfigurationSpec extends ApplicationContextSpecification {

    @Subject
    @Shared
    SecuritySessionConfiguration sessionConfiguration = applicationContext.getBean(SecuritySessionConfiguration)

    @Deprecated
    void "it is possible to override success and failure urls via configuration"() {
        expect:
        sessionConfiguration.loginSuccessTargetUrl == '/'
        sessionConfiguration.logoutTargetUrl == '/'
        sessionConfiguration.loginFailureTargetUrl == '/'
        sessionConfiguration.unauthorizedTargetUrl == '/'
        sessionConfiguration.forbiddenTargetUrl == '/'
        sessionConfiguration.redirectOnRejection
    }

}
