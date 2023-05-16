package io.micronaut.security.token.paseto

import dev.paseto.jpaseto.Version
import dev.paseto.jpaseto.lang.Keys
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.generator.TokenGenerator
import io.micronaut.security.token.paseto.config.RequiredConfiguration
import io.micronaut.security.token.paseto.config.VersionedSharedSecretConfiguration
import io.micronaut.security.token.paseto.generator.PasetoTokenGenerator
import io.micronaut.security.token.paseto.validator.PasetoTokenValidator
import io.micronaut.security.token.render.BearerAccessRefreshToken
import io.micronaut.security.token.validator.TokenValidator
import jakarta.inject.Singleton

import jakarta.annotation.security.RolesAllowed
import java.security.Principal

class PasetoLoginSpec extends EmbeddedServerSpecification {
    @Override
    String getSpecName() {
        'PasetoLoginSpec'
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.authentication': 'bearer',
                'micronaut.security.token.paseto.local-generator.version': 'v1',
                'micronaut.security.token.paseto.local-generator.base64-shared-secret': generateSharedSecret()
        ]
    }

    void "you can login and obtain a paseto token"() {
        expect: 'a token generator of type PasetoTokenGenerator exists'
        containsBean(RequiredConfiguration)
        getBean(VersionedSharedSecretConfiguration).version == Version.V1
        containsBean(TokenGenerator)
        containsBean(TokenValidator)
        getBean(TokenGenerator) instanceof PasetoTokenGenerator
        getBean(TokenValidator) instanceof PasetoTokenValidator

        when:
        HttpRequest<?> request = HttpRequest.POST('/login', [username: 'sherlock', password: 'elementary'])
        BearerAccessRefreshToken bearerAccessRefreshToken = client.retrieve(request, BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        'sherlock' == bearerAccessRefreshToken.username

        when:
        String username = client.retrieve(HttpRequest.GET('/username')
                .bearerAuth(bearerAccessRefreshToken.accessToken)
                .accept(MediaType.TEXT_PLAIN))

        then:
        noExceptionThrown()
        'sherlock' == username
    }

    private static String generateSharedSecret() {
        Base64.getEncoder().encodeToString(Keys.secretKey().getEncoded())
    }

    @Requires(property = 'spec.name', value = 'PasetoLoginSpec')
    @Controller
    static class EchoUserNameController {

        @RolesAllowed("ROLE_DETECTIVE")
        @Get("/username")
        @Produces(MediaType.TEXT_PLAIN)
        String index(Principal principal) {
            principal.name
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'PasetoLoginSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new  SuccessAuthenticationScenario('sherlock', ['ROLE_DETECTIVE'])])
        }
    }
}
