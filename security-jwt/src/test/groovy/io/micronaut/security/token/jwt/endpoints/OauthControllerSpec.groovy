package io.micronaut.security.token.jwt.endpoints

import com.fasterxml.jackson.annotation.JsonProperty
import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.context.exceptions.NoSuchBeanException
import io.micronaut.core.annotation.Introspected
import io.micronaut.core.async.publisher.Publishers
import io.micronaut.core.type.Argument
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.inject.qualifiers.Qualifiers
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.render.AccessRefreshToken
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.micronaut.security.token.refresh.RefreshTokenPersistence
import io.micronaut.security.token.validator.TokenValidator
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import javax.inject.Singleton

class OauthControllerSpec extends Specification {

    @Shared
    @AutoCleanup
    ApplicationContext context = ApplicationContext.run(
            [
                    'spec.name': 'endpoints',
                    'micronaut.security.endpoints.login.enabled': true,
                    'micronaut.security.endpoints.oauth.enabled': true,
                    'micronaut.security.token.jwt.generator.refresh-token.enabled': true,
                    'micronaut.security.token.jwt.generator.refresh-token.secret': 'abc',
                    'micronaut.security.token.jwt.signatures.secret.generator.secret': 'qrD6h8K6S9503Q06Y6Rfk21TErImPYqa'
            ], Environment.TEST)

    @Shared
    EmbeddedServer embeddedServer = context.getBean(EmbeddedServer).start()

    @Shared
    @AutoCleanup
    HttpClient client = context.createBean(HttpClient, embeddedServer.getURL())

    def "can obtain a new access token using the refresh token"() {
        expect:
        context.getBean(SignatureConfiguration.class)
        context.getBean(SignatureConfiguration.class, Qualifiers.byName("generator"))

        when:
        context.getBean(EncryptionConfiguration.class)

        then:
        thrown(NoSuchBeanException)

        when:
        def creds = new UsernamePasswordCredentials('user', 'password')
        HttpResponse rsp = client.toBlocking().exchange(HttpRequest.POST('/login', creds), BearerAccessRefreshToken)

        then:
        rsp.status() == HttpStatus.OK
        rsp.body().accessToken
        rsp.body().refreshToken

        when:
        sleep(1_000) // Sleep for one second to give time for Claims issue date to be different
        final String originalAccessToken = rsp.body().accessToken
        String refreshToken = rsp.body().refreshToken
        def tokenRefreshReq = new TokenRefreshRequest(refreshToken)
        HttpResponse refreshRsp = client.toBlocking().exchange(HttpRequest.POST('/oauth/access_token', tokenRefreshReq), AccessRefreshToken)

        then:
        refreshRsp.status() == HttpStatus.OK
        refreshRsp.body().accessToken
        and:
        refreshRsp.body().accessToken != originalAccessToken

        when:
        TokenValidator tokenValidator = context.getBean(JwtTokenValidator.class)
        Map<String, Object> newAccessTokenClaims = Flowable.fromPublisher(tokenValidator.validateToken(refreshRsp.body().accessToken)).blockingFirst().getAttributes()
        Map<String, Object> originalAccessTokenClaims = Flowable.fromPublisher(tokenValidator.validateToken(originalAccessToken)).blockingFirst().getAttributes()
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
    }

    void "grant_type other than refresh_token returns 400 with {\"error\": \"unsupported_grant_type\"...}"() {
        given:
        HttpRequest request = HttpRequest.POST('/oauth/access_token', new TokenRefreshRequest("foo", "XXX"))

        when:
        Argument<AccessRefreshToken> bodyType = Argument.of(AccessRefreshToken)
        Argument<CustomErrorResponse> errorType = Argument.of(CustomErrorResponse)
        client.toBlocking().exchange(request, bodyType, errorType)

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
        HttpRequest request = HttpRequest.POST('/oauth/access_token', new TokenRefreshRequest(grantType, refreshToken))

        when:
        Argument<AccessRefreshToken> bodyType =  Argument.of(AccessRefreshToken)
        Argument<CustomErrorResponse> errorType =  Argument.of(CustomErrorResponse)
        client.toBlocking().exchange(request, bodyType, errorType)

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

    @Singleton
    static class InMemoryRefreshTokenPersistence implements RefreshTokenPersistence {

        Map<String, UserDetails> tokens = [:]

        @Override
        void persistToken(RefreshTokenGeneratedEvent event) {
            tokens.put(event.getRefreshToken(), event.getUserDetails())
        }

        @Override
        Publisher<UserDetails> getUserDetails(String refreshToken) {
            Publishers.just(tokens.get(refreshToken))
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
