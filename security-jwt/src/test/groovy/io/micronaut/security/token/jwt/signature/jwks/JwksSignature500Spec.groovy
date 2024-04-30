package io.micronaut.security.token.jwt.signature.jwks

import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.ApplicationContext
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.JwtFixture
import io.micronaut.security.token.jwt.nimbus.ReactiveJwksSignature
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class JwksSignature500Spec extends Specification implements JwtFixture {

    static final String SPEC_NAME_PROPERTY = 'spec.name'

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer, [
            (SPEC_NAME_PROPERTY) : 'jwkssignature500spec',
    ])

    void "if the remote JWKS endpoint throws 500, the JwksSignature handles it and it does not crash"() {
        given:
        ApplicationContext context = ApplicationContext.run([
                'micronaut.security.token.jwt.signatures.jwks.awscognito.url':  "http://localhost:${embeddedServer.getPort()}/keys",
        ])

        when:
        Collection<ReactiveJwksSignature> beans = context.getBeansOfType(ReactiveJwksSignature)

        then:
        beans

        when:
        ReactiveJwksSignature jwksSignature = beans[0]
        SignedJWT signedJWT = generateSignedJWT()

        then:
        !Mono.from(jwksSignature.verify(signedJWT)).block()

        and:
        noExceptionThrown()

        when:
        FooController fooController = embeddedServer.applicationContext.getBean(FooController)

        then:
        noExceptionThrown()

        and: // calls the JWKS endpoint several times (first attempt and the configured number of attempts)
        //fooController.called == 3 /* JwksSignature::supportedAlgorithmsMessage JwksSignature:::supports JwksSignature::::verify */

        cleanup:
        context.close()
    }

    @Requires(property = "spec.name", value = "jwkssignature500spec")
    @Controller("/keys")
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class FooController {

        int called = 0

        @Get
        HttpResponse index() {
            called++
            HttpResponse.serverError()
        }
    }

}
