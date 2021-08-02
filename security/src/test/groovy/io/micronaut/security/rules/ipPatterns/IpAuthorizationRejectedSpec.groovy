package io.micronaut.security.rules.ipPatterns

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.MockAuthenticationProvider
import io.micronaut.security.SuccessAuthenticationScenario
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import jakarta.inject.Singleton

class IpAuthorizationRejectedSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'IpAuthorizationRejectedSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.ip-patterns': ['10.10.0.48', '127.0.0.*']
        ]
    }

    void "if you are in the correct ip range, accessing the secured controller with authentication should be successful"() {
        when:
        HttpRequest req = HttpRequest.GET("/secured/authenticated")
                .basicAuth("user", "password")
        client.exchange(req, String)

        then:
        noExceptionThrown()
    }

    @Requires(property = 'spec.name', value = 'IpAuthorizationRejectedSpec')
    @Controller("/secured")
    @Secured(SecurityRule.IS_AUTHENTICATED)
    static class SecuredController {

        @Get("/authenticated")
        String authenticated(Authentication authentication) {
            "${authentication.getName()} is authenticated"
        }
    }

    @Requires(property = 'spec.name', value = 'IpAuthorizationRejectedSpec')
    @Singleton
    static class CustomAuthenticationProvider extends MockAuthenticationProvider {

        CustomAuthenticationProvider() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }
}
