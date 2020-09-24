package io.micronaut.security.token.jwt.validator

import edu.umd.cs.findbugs.annotations.NonNull
import edu.umd.cs.findbugs.annotations.Nullable
import groovy.transform.InheritConstructors
import io.micronaut.context.annotation.Replaces
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
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.validator.TokenValidator
import io.micronaut.testutils.EmbeddedServerSpecification
import io.reactivex.BackpressureStrategy
import io.reactivex.Flowable
import org.reactivestreams.Publisher

import javax.inject.Singleton
import java.security.Principal

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
    @Replaces(JwtTokenValidator)
    static class CustomJwtTokenValidator extends JwtTokenValidator {
        CustomJwtTokenValidator(Collection<SignatureConfiguration> signatureConfigurations,
                                Collection<EncryptionConfiguration> encryptionConfigurations,
                                Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
                                JwtAuthenticationFactory jwtAuthenticationFactory) {
            super(signatureConfigurations, encryptionConfigurations, genericJwtClaimsValidators, jwtAuthenticationFactory)
        }

        @Override
        @Deprecated
        Publisher<Authentication> validateToken(String token, HttpRequest<?> request) {
            return validator.validate(token, request)
                    .flatMap(jwtAuthenticationFactory::createAuthentication)
                    .map(Flowable::just)
                    .orElse(Flowable.empty());
        }
    }

    @Requires(property = 'spec.name', value = 'JwtClaimsValidatorRequestPassedSpec')
    @Singleton
    static class HttpRequestClaimsValidator implements GenericJwtClaimsValidator {

        @Override
        boolean validate(JwtClaims claims) {
            false
        }

        @Override
        boolean validate(@NonNull JwtClaims claims, @Nullable HttpRequest<?> request) {
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
