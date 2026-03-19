package io.micronaut.security.token.jwt.validator

import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.*
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.scheduling.TaskExecutors
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.Claims
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.nimbus.NimbusReactiveJsonWebTokenValidator
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration
import io.micronaut.security.token.render.BearerAccessRefreshToken
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import jakarta.inject.Named
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux

import java.security.Principal
import java.util.concurrent.ExecutorService

class JwtClaimsValidatorRequestPassedSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'JwtClaimsValidatorRequestPassedSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.security.authentication'   : 'bearer',
        ]
    }

    def "by default JwtClaimsValidator which expects request is invoked if you replace JwtTokenValidator"() {
        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken

        when:
        final String accessToken =  rsp.body().accessToken
        HttpRequest request = HttpRequest.GET("/echo/user")
                .accept(MediaType.TEXT_PLAIN)
                .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
        client.exchange(request)

        then: // no 401 is thrown because GenericJwtClaimsValidator::validate is invoked claims, req and request is not null
        noExceptionThrown()
    }

    @Requires(property = 'spec.name', value = 'JwtClaimsValidatorRequestPassedSpec')
    @Singleton
    static class HttpRequestClaimsValidator<T> implements GenericJwtClaimsValidator<T> {

        @Override
        boolean validate(@NonNull Claims claims, @Nullable T request) {
            request != null
        }
    }

    @Controller("/echo/user")
    @Requires(property = 'spec.name', value = 'JwtClaimsValidatorRequestPassedSpec')
    static class EchoController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Principal principal) {
            principal.name
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'JwtClaimsValidatorRequestPassedSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {

        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }
}
