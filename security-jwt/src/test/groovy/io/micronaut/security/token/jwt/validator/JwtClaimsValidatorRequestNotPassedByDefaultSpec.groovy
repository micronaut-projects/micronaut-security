package io.micronaut.security.token.jwt.validator

import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.testutils.EmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton
import java.security.Principal

class JwtClaimsValidatorRequestNotPassedByDefaultSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'JwtClaimsValidatorRequestNotPassedByDefaultSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.security.authentication'   : 'bearer',
        ]
    }
    
    @Requires(property = 'spec.name', value = 'JwtClaimsValidatorRequestNotPassedByDefaultSpec')
    @Singleton
    static class HttpRequestClaimsValidator implements GenericJwtClaimsValidator {

        @Override
        boolean validate(JwtClaims claims) {
            false
        }

        @Override
        boolean validate(@NonNull JwtClaims claims, @Nullable HttpRequest<?> request) {
            request == null
        }
    }

    @Controller("/echo/user")
    @Requires(property = 'spec.name', value = 'JwtClaimsValidatorRequestNotPassedByDefaultSpec')
    static class EchoController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index(Principal principal) {
            principal.name
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'JwtClaimsValidatorRequestNotPassedByDefaultSpec')
    static class AuthenticationProviderUserPassword implements AuthenticationProvider {

        @Override
        Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Flowable.create({ emitter ->
                if (authenticationRequest.identity == 'user' && authenticationRequest.secret == 'password') {
                    emitter.onNext(new UserDetails('user', []))
                    emitter.onComplete()
                } else {
                    emitter.onError(new AuthenticationException(new AuthenticationFailed()))
                }

            }, BackpressureStrategy.ERROR)
        }
    }
}
