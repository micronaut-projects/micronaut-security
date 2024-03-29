package io.micronaut.security.x509

import io.micronaut.context.annotation.Requires
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication

import static io.micronaut.security.rules.SecurityRule.IS_AUTHENTICATED

class X509AuthenticationFetcherSpec extends AbstractX509Spec {

    private static final String SPEC_NAME = 'X509AuthenticationFetcherSpec'

    @Override
    String getSpecName() {
        SPEC_NAME
    }

    void 'test X509AuthenticationFetcher'() {
        expect:
        applicationContext.getBean(X509AuthenticationFetcher)

        and:
        'x509test' == client.retrieve('/x509')
    }

    @Requires(property = 'spec.name', value = SPEC_NAME)
    @Secured(IS_AUTHENTICATED)
    @Controller('/x509')
    static class X509Controller {
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String username(Authentication authentication) {
            authentication.name
        }
    }
}
