package io.micronaut.security.x509

import io.micronaut.context.annotation.Requires
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
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
        embeddedServer.applicationContext.getBean X509AuthenticationFetcher

        and:
        'x509test' == client.retrieve('/x509')

        and:
        X509Controller.authentication
        X509Controller.x509Authentication
        X509Controller.authentication.is X509Controller.x509Authentication
    }

    @Requires(property = 'spec.name', value = SPEC_NAME)
    @Secured(IS_AUTHENTICATED)
    @Controller('/x509')
    static class X509Controller {

        static Authentication authentication
        static X509Authentication x509Authentication

        @Get
        String username(Authentication auth,
                        X509Authentication x509Auth) {

            authentication = auth
            x509Authentication = x509Auth

            auth.name
        }
    }
}
