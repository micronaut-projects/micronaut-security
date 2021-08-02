package io.micronaut.security.token.jwt.endpoints

import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.jose.JWSObject
import io.micronaut.context.annotation.Requires
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.core.annotation.Introspected
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.security.annotation.Secured
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.testutils.EmbeddedServerSpecification
import io.micronaut.security.testutils.authprovider.MockAuthenticationProvider
import io.micronaut.security.testutils.authprovider.SuccessAuthenticationScenario
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.render.AccessRefreshToken
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.security.token.validator.TokenValidator
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Flux
import spock.lang.Unroll

import java.security.Principal

class OauthControllerSpec extends EmbeddedServerSpecification {

    @Override
    Map<String, Object> getConfiguration() {
        super.configuration + [
                'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa',
                'micronaut.security.token.jwt.generator.refresh-token.secret': 'pleaseChangeThisSecretForANewOne',
                'micronaut.security.authentication': 'bearer',
         ] as Map<String, Object>
    }

    @Override
    String getSpecName() {
        'OauthControllerSpec'
    }

    def "can obtain a new access token using the refresh token"() {
        expect:
        applicationContext.getBean(SignatureConfiguration.class)
        applicationContext.getBean(SignatureConfiguration.class, Qualifiers.byName("generator"))

        when:
        applicationContext.getBean(EncryptionConfiguration.class)

        then:
        thrown(NoSuchBeanException)

        when:
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse<BearerAccessRefreshToken> rsp = client.exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        rsp.status() == HttpStatus.OK

        when:
        BearerAccessRefreshToken accessRefreshToken = rsp.body()

        then:
        accessRefreshToken.accessToken
        accessRefreshToken.refreshToken

        when: 'refresh token is a JWS'
        JWSObject.parse(accessRefreshToken.refreshToken)

        then:
        noExceptionThrown()

        when: 'it is possible to access a secured endpoint with an access token'
        String name = client.retrieve(HttpRequest.GET('/echoname').accept(MediaType.TEXT_PLAIN).bearerAuth(accessRefreshToken.accessToken), String)

        then:
        noExceptionThrown()
        name == 'user'

        when: 'it is not possible to access a secured endpoint with a refresh token'
        client.retrieve(HttpRequest.GET('/echoname').accept(MediaType.TEXT_PLAIN).bearerAuth(accessRefreshToken.refreshToken))

        then:
        HttpClientResponseException e = thrown()
        e.status == HttpStatus.UNAUTHORIZED

        when:
        sleep(1_000) // Sleep for one second to give time for Claims issue date to be different
        String originalAccessToken = accessRefreshToken.accessToken
        String refreshToken = accessRefreshToken.refreshToken
        TokenRefreshRequest tokenRefreshReq = new TokenRefreshRequest(refreshToken)
        HttpResponse<BearerAccessRefreshToken> refreshRsp = client.exchange(HttpRequest.POST('/oauth/access_token', tokenRefreshReq), BearerAccessRefreshToken)

        then:
        noExceptionThrown()
        refreshRsp.status() == HttpStatus.OK

        when:
        accessRefreshToken = refreshRsp.body()

        then:
        accessRefreshToken.accessToken
        accessRefreshToken.accessToken != originalAccessToken

        when:
        TokenValidator tokenValidator = applicationContext.getBean(JwtTokenValidator.class)
        Map<String, Object> newAccessTokenClaims = Flux.from(tokenValidator.validateToken(refreshRsp.body().accessToken, null)).blockFirst().getAttributes()
        Map<String, Object> originalAccessTokenClaims = Flux.from(tokenValidator.validateToken(originalAccessToken, null)).blockFirst().getAttributes()
        List<String> expectedClaims = [JwtClaims.SUBJECT,
                                       JwtClaims.ISSUED_AT,
                                       JwtClaims.EXPIRATION_TIME,
                                       JwtClaims.NOT_BEFORE,
                                       "roles"]
        then:
        expectedClaims.each { String claimName ->
            assert newAccessTokenClaims.containsKey(claimName)
            assert originalAccessTokenClaims.containsKey(claimName)
        }
        originalAccessTokenClaims.get(JwtClaims.SUBJECT) == newAccessTokenClaims.get(JwtClaims.SUBJECT)
        originalAccessTokenClaims.get("roles") == newAccessTokenClaims.get("roles")
        originalAccessTokenClaims.get(JwtClaims.ISSUED_AT) != newAccessTokenClaims.get(JwtClaims.ISSUED_AT)
        originalAccessTokenClaims.get(JwtClaims.EXPIRATION_TIME) != newAccessTokenClaims.get(JwtClaims.EXPIRATION_TIME)
        originalAccessTokenClaims.get(JwtClaims.NOT_BEFORE) != newAccessTokenClaims.get(JwtClaims.NOT_BEFORE)

        cleanup:
        applicationContext.getBean(InMemoryRefreshTokenPersistence).tokens.clear()
    }

    void "trying to get a new access token with an unsigned refresh token throws exception"() {
        given:
        String refreshToken = 'XXX'

        when:
        TokenRefreshRequest tokenRefreshReq = new TokenRefreshRequest(refreshToken)
        Argument<AccessRefreshToken> bodyType = Argument.of(AccessRefreshToken)
        Argument<CustomErrorResponse> errorType = Argument.of(CustomErrorResponse)
        client.exchange(HttpRequest.POST('/oauth/access_token', tokenRefreshReq), bodyType, errorType)

        then:
        HttpClientResponseException e = thrown()
        e.response.status() == HttpStatus.BAD_REQUEST

        when:
        Optional<CustomErrorResponse> errorResponseOptional = e.response.getBody(CustomErrorResponse)

        then:
        errorResponseOptional.isPresent()

        when:
        CustomErrorResponse errorResponse = errorResponseOptional.get()

        then:
        errorResponse.error
        errorResponse.error == 'invalid_grant'
        errorResponse.errorDescription == 'Refresh token is invalid'
    }

    void "grant_type other than refresh_token returns 400 with {\"error\": \"unsupported_grant_type\"...}"() {
        given:
        HttpRequest request = HttpRequest.POST('/oauth/access_token', [grant_type: 'foo', refresh_token: "XXX"])

        when:
        Argument<AccessRefreshToken> bodyType = Argument.of(AccessRefreshToken)
        Argument<CustomErrorResponse> errorType = Argument.of(CustomErrorResponse)
        client.exchange(request, bodyType, errorType)

        then:
        HttpClientResponseException e = thrown()
        e.response.status() == HttpStatus.BAD_REQUEST

        when:
        Optional<CustomErrorResponse> errorResponseOptional = e.response.getBody(CustomErrorResponse)

        then:
        errorResponseOptional.isPresent()

        when:
        CustomErrorResponse errorResponse = errorResponseOptional.get()

        then:
        errorResponse.error
        errorResponse.error == 'unsupported_grant_type'
        errorResponse.errorDescription == 'grant_type must be refresh_token'
    }

    @Unroll
    void "missing #paramName returns 400 with {\"error\": \"invalid_request\"...}"(String grantType, String refreshToken, String paramName) {
        given:
        Map<String, Object> body = new HashMap<>()
        if (grantType) {
            body.grant_type = grantType
        }
        if (refreshToken)  {
            body.refresh_token = refreshToken
        }
        HttpRequest request = HttpRequest.POST('/oauth/access_token', body)

        when:
        Argument<AccessRefreshToken> bodyType =  Argument.of(AccessRefreshToken)
        Argument<CustomErrorResponse> errorType =  Argument.of(CustomErrorResponse)
        client.exchange(request, bodyType, errorType)

        then:
        HttpClientResponseException e = thrown()
        e.response.status() == HttpStatus.BAD_REQUEST

        when:
        Optional<CustomErrorResponse> errorResponseOptional = e.response.getBody(CustomErrorResponse)

        then:
        errorResponseOptional.isPresent()

        when:
        CustomErrorResponse errorResponse = errorResponseOptional.get()

        then:
        errorResponse.error
        errorResponse.error == 'invalid_request'
        errorResponse.errorDescription == 'refresh_token and grant_type are required'

        where:
        grantType       | refreshToken
        'refresh_token' | null
        null            | 'XXXX'

        paramName = grantType == null ? 'grant_type' : (refreshToken == null ? 'refresh_token': '')
    }

    @Requires(property = 'spec.name', value = 'OauthControllerSpec')
    @Controller("/echoname")
    static class EchoNameController {

        @Produces(MediaType.TEXT_PLAIN)
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        String index(Principal principal) {
            principal.name
        }
    }

    @Requires(property = 'spec.name', value = 'OauthControllerSpec')
    @Singleton
    static class InMemoryRefreshTokenPersistence implements RefreshTokenPersistence {

        Map<String, Authentication> tokens = [:]

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.getRefreshToken(), event.getAuthentication())
        }

        @Override
        Publisher<Authentication> getAuthentication(String refreshToken) {
            Publishers.just(tokens.get(refreshToken))
        }
    }

    @Singleton
    @Requires(property = 'spec.name', value = 'OauthControllerSpec')
    static class AuthenticationProviderUserPassword extends MockAuthenticationProvider {
        AuthenticationProviderUserPassword() {
            super([new SuccessAuthenticationScenario('user')])
        }
    }

    @Introspected
    static class CustomErrorResponse {
        String error

        @JsonProperty("error_description")
        String errorDescription

        @JsonProperty("error_uri")
        String errorUri
    }
}
