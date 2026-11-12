package io.micronaut.security.token.jwt.nimbus

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.jwt.config.JwtConfiguration
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.validator.JsonWebTokenValidator
import io.micronaut.security.token.jwt.validator.ReactiveJsonWebTokenValidator
import io.micronaut.security.token.render.BearerAccessRefreshToken
import jakarta.inject.Singleton
import reactor.core.publisher.Mono

/**
 * With {@code micronaut.security.token.jwt.accept-unsigned-tokens=true} and no signature configuration,
 * unsigned JWTs (alg=none) are accepted. This is an explicit opt-in: such tokens can be forged by anyone.
 */
class UnsignedJwtAcceptedWhenOptInSpec extends EmbeddedServerSpecification {

    @Override
    String getSpecName() {
        'UnsignedJwtAcceptedWhenOptInSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'bearer',
                'micronaut.security.token.jwt.accept-unsigned-tokens': true,
        ]
    }

    void "accept-unsigned-tokens is bound and no signature configuration is present"() {
        expect:
        applicationContext.getBean(JwtConfiguration).acceptUnsignedTokens
        applicationContext.getBeansOfType(SignatureConfiguration).isEmpty()
    }

    void "an unsigned token issued by login is accepted when accept-unsigned-tokens is true"() {
        when:
        HttpResponse<BearerAccessRefreshToken> loginRsp = client.exchange(HttpRequest.POST('/login', new UsernamePasswordCredentials('sherlock', 'password')), BearerAccessRefreshToken)

        then:
        loginRsp.status() == HttpStatus.OK
        String accessToken = loginRsp.body().accessToken
        JWTParser.parse(accessToken) instanceof PlainJWT

        when:
        HttpResponse<String> rsp = client.exchange(HttpRequest.GET('/secured').bearerAuth(accessToken), String)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body() == 'sherlock'

        and: 'both validators accept it'
        applicationContext.getBean(JsonWebTokenValidator).validate(accessToken, null).isPresent()
        Mono.from(applicationContext.getBean(ReactiveJsonWebTokenValidator).validate(accessToken, null)).blockOptional().isPresent()
    }

    void "opting in means a forged alg=none token is accepted too, which is why the default is false"() {
        given:
        String forged = new PlainJWT(new JWTClaimsSet.Builder().subject('mallory').build()).serialize()

        when:
        HttpResponse<String> rsp = client.exchange(HttpRequest.GET('/secured').bearerAuth(forged), String)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body() == 'mallory'
    }

    @Requires(property = 'spec.name', value = 'UnsignedJwtAcceptedWhenOptInSpec')
    @Singleton
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('sherlock')])
        }
    }

    @Requires(property = 'spec.name', value = 'UnsignedJwtAcceptedWhenOptInSpec')
    @Controller
    static class SecuredController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get('/secured')
        String secured(java.security.Principal principal) {
            principal.name
        }
    }
}
