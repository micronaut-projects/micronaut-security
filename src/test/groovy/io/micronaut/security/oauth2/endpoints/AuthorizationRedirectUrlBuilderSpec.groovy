package io.micronaut.security.oauth2.endpoints

import io.micronaut.context.ApplicationContext
import io.micronaut.security.oauth2.openid.endpoints.authorization.AuthenticationRequest
import io.micronaut.security.oauth2.openid.endpoints.authorization.AuthorizationRedirectUrlBuilder
import io.micronaut.security.oauth2.openid.endpoints.authorization.Display
import io.micronaut.security.oauth2.openid.endpoints.authorization.Prompt
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class AuthorizationRedirectUrlBuilderSpec extends Specification {

    @AutoCleanup
    @Shared
    ApplicationContext applicationContext = ApplicationContext.run([
            'micronaut.security.enabled': true,]
    )

    void "verify a oauth2 flow can be created to consume Translate API"() {
        given:
        AuthenticationRequest authenticationRequest = new AuthenticationRequest() {
            @Override
            String getClientId() {
                return '407408718192.apps.googleusercontent.com'
            }

            @Override
            String getState() {
                return null
            }

            @Override
            String getNonce() {
                return null
            }

            @Override
            String getLoginHint() {
                return null
            }

            @Override
            String getIdTokenHint() {
                return null
            }

            @Override
            List<String> getScopes() {
                ['https://www.googleapis.com/auth/cloud-platform',
                 'https://www.googleapis.com/auth/cloud-translation']
            }

            @Override
            String getResponseType() {
                return 'code'
            }

            @Override
            String getRedirectUri() {
                return 'https://developers.google.com/oauthplayground'
            }

            @Override
            String getResponseMode() {
                return null
            }

            @Override
            Display getDisplay() {
                return null
            }

            @Override
            Prompt getPrompt() {
                return Prompt.CONSENT
            }

            @Override
            Integer getMaxAge() {
                return null
            }

            @Override
            List<String> getUiLocales() {
                return null
            }

            @Override
            List<String> getAcrValues() {
                return null
            }
        }

        expect:
        applicationContext.containsBean(AuthorizationRedirectUrlBuilder)

        when:
        String googleAuthorizationEndpoint = 'https://accounts.google.com/o/oauth2/v2/auth'
        AuthorizationRedirectUrlBuilder redirectUrlBuilder = applicationContext.getBean(AuthorizationRedirectUrlBuilder)
        String uri = redirectUrlBuilder.resolveAuthorizationRedirectUrl(authenticationRequest, googleAuthorizationEndpoint)

        String expected = 'https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&prompt=consent&response_type=code&client_id=407408718192.apps.googleusercontent.com&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-translation'

        String[] arr = expected.split('\\?')
        String[] params = arr[1].split('&')
        String[] resultArr = uri.split('\\?')
        String[] resultParams = resultArr[1].split('&')

        then:
        arr[0] == resultArr[0]
        resultParams.each { String param ->
            assert params.contains(param)
        }

    }
}
