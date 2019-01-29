package io.micronaut.security.oauth2.openid.endpoints.authorization

import com.stehno.ersatz.ContentType
import com.stehno.ersatz.ErsatzServer
import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderMetadata
import spock.lang.Specification

class DefaultAuthorizationRedirectUrlProviderSpec extends Specification {

    private static final SPEC_NAME_PROPERTY = 'spec.name'

    void "AuthorizationRedirectUrlProvider build a url"() {
        given:
        String openIdConfigurationJson = 'src/test/resources/aws-cognito-openid-configuration.json'
        String path = '/eu-west-1_ZLiEFD4b6/.well-known/openid-configuration'
        File jsonFile = new File(openIdConfigurationJson)
        assert jsonFile.exists()

        and:
        ErsatzServer ersatz = new ErsatzServer()
        ersatz.expectations {
            get(path) {
                called 1
                responder {
                    body(jsonFile.text, ContentType.APPLICATION_JSON)
                }
            }
        }

        and:
        String openIdConfigurationEndpoint = "${ersatz.httpUrl}$path"
        ApplicationContext context = ApplicationContext.run([
            (SPEC_NAME_PROPERTY)                            : getClass().simpleName,
            'micronaut.security.enabled'                    : true,
            'micronaut.security.oauth2.client-id'           : 'XXXX',
            'micronaut.security.oauth2.openid-configuration': openIdConfigurationEndpoint
        ], Environment.TEST)

        when:
        context.getBean(AuthenticationRequestProvider)

        then:
        noExceptionThrown()

        when:
        context.getBean(OpenIdProviderMetadata)

        then:
        noExceptionThrown()

        when:
        AuthorizationRedirectUrlProvider authorizationRedirectUrlProvider = context.getBean(AuthorizationRedirectUrlProvider)

        then:
        noExceptionThrown()

        and:
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().startsWith( "https://micronautguides.auth.eu-west-1.amazoncognito.com/oauth2/authorize")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("response_type=code")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("scope=openid")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("client_id=XXXX")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("response_mode=query")
        authorizationRedirectUrlProvider.resolveAuthorizationRedirectUrl().contains("redirect_uri")

        and:
        ersatz.verify()

        cleanup:
        ersatz.stop()

        and:
        context.close()
    }
}
