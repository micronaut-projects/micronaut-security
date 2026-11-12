package io.micronaut.security.oauth2.endpoint.token.response

import com.nimbusds.jwt.JWTClaimsSet
import io.micronaut.security.authentication.AuthenticationMode
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.config.AuthenticationModeConfiguration
import io.micronaut.security.oauth2.configuration.OpenIdAdditionalClaimsConfiguration
import reactor.core.publisher.Flux
import spock.lang.Specification

class DefaultOpenIdAuthenticationMapperSpec extends Specification {

    void "refreshToken attribute is #description when authentication mode is #mode, additional claims refresh-token is #refreshTokenClaim and the token response refresh_token is #refreshToken"() {
        given:
        DefaultOpenIdAuthenticationMapper mapper = new DefaultOpenIdAuthenticationMapper(
                additionalClaims(refreshTokenClaim),
                authenticationMode(mode))
        OpenIdTokenResponse tokenResponse = new OpenIdTokenResponse()
        tokenResponse.idToken = 'idToken'
        tokenResponse.accessToken = 'accessToken'
        tokenResponse.tokenType = 'bearer'
        tokenResponse.refreshToken = refreshToken
        OpenIdClaims openIdClaims = new JWTOpenIdClaims(new JWTClaimsSet.Builder().subject('sherlock').build())

        when:
        AuthenticationResponse response = Flux.from(mapper.createAuthenticationResponse('okta', tokenResponse, openIdClaims, null)).blockFirst()

        then:
        response.authenticated
        Map<String, Object> attributes = response.authentication.get().attributes
        attributes.containsKey(OauthAuthenticationMapper.REFRESH_TOKEN_KEY) == present
        attributes.get(OauthAuthenticationMapper.REFRESH_TOKEN_KEY) == (present ? refreshToken : null)
        !attributes.values().any { it == null }

        where:
        mode                       | refreshTokenClaim | refreshToken   | present
        AuthenticationMode.IDTOKEN | false             | null           | false
        AuthenticationMode.IDTOKEN | false             | 'refreshToken' | true
        null                       | true              | null           | false
        null                       | true              | 'refreshToken' | true
        null                       | false             | 'refreshToken' | false
        description = present ? 'present' : 'absent'
    }

    private static OpenIdAdditionalClaimsConfiguration additionalClaims(boolean refreshToken) {
        new OpenIdAdditionalClaimsConfiguration() {
            @Override
            boolean isJwt() {
                false
            }

            @Override
            boolean isAccessToken() {
                false
            }

            @Override
            boolean isRefreshToken() {
                refreshToken
            }
        }
    }

    private static AuthenticationModeConfiguration authenticationMode(AuthenticationMode mode) {
        new AuthenticationModeConfiguration() {
            @Override
            AuthenticationMode getAuthentication() {
                mode
            }
        }
    }
}
