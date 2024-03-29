package io.micronaut.security.x509

import io.micronaut.context.annotation.Requires
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication

import static io.micronaut.security.rules.SecurityRule.IS_AUTHENTICATED

class X509AuthenticationArgumentBinderSpec extends AbstractX509Spec {

    private static final String SPEC_NAME = 'X509AuthenticationArgumentBinderSpec'

    @Override
    String getSpecName() {
        SPEC_NAME
    }

    void 'test X509AuthenticationFetcher'() {
        expect:
        applicationContext.containsBean(X509AuthenticationFetcher)

        when:
        X509Controller controller = applicationContext.getBean(X509Controller)

        then:
        !controller.authentication
        !controller.x509Authentication

        and:
        'x509test' == client.retrieve('/x509')

        and:
        controller.authentication
        controller.x509Authentication
        controller.authentication.is(controller.x509Authentication)
    }

    @Requires(property = 'spec.name', value = SPEC_NAME)
    @Secured(IS_AUTHENTICATED)
    @Controller('/x509')
    static class X509Controller {

        Authentication authentication
        X509Authentication x509Authentication

        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication auth,
                        X509Authentication x509Auth) {
            authentication = auth
            x509Authentication = x509Auth
            auth.name
        }
    }
}
