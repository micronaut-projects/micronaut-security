package io.micronaut.security.aot

import io.micronaut.aot.core.AOTCodeGenerator
import io.micronaut.aot.core.codegen.AbstractSourceGeneratorSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.context.ApplicationContextBuilder
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import spock.lang.AutoCleanup
import spock.lang.Shared

class OpenIdProviderMetadataFetcherCodeGeneratorSpec extends AbstractSourceGeneratorSpec {

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer,
            ['spec.name': 'EmbeddedServerOpenIdProviderMetadataFetcherCodeGeneratorSpec'],
            Environment.TEST)

    @Override
    protected void customizeContext(ApplicationContextBuilder builder) {
        builder = builder.properties([
                'micronaut.security.oauth2.clients.cognito.client-id': 'XXX',
                'micronaut.security.oauth2.clients.cognito.client-secret': 'YYY',
                'micronaut.security.oauth2.clients.cognito.openid.issuer': "http://localhost:$embeddedServer.port",
        ])
        builder.environments(Environment.TEST)
        super.customizeContext(builder)
    }

    @Override
    AOTCodeGenerator newGenerator() {
        return new OpenIdProviderMetadataFetcherCodeGenerator()
    }

    void "verify OpenIdProviderMetadataFetcherCodeGenerator generates OpenIdProviderMetadataFetcher per openid client"() {
        expect:
        embeddedServer.applicationContext.containsBean(OpenIdConfigurationController)

        when:
        generate()

        then:
        assertThatGeneratedSources {
            hasClass("AotOpenIdProviderMetadataFetcherCognito") {
                withSources("foo")
            }
        }
    }

    @Requires(property = 'spec.name', value = 'EmbeddedServerOpenIdProviderMetadataFetcherCodeGeneratorSpec')
    @Controller
    static class OpenIdConfigurationController {

        @Get("/.well-known/openid-configuration")
        @Secured(SecurityRule.IS_ANONYMOUS)
        String index() {
            '{"authorization_endpoint":"https://auth-groovycalamari.auth.us-east-1.amazoncognito.com/oauth2/authorize","id_token_signing_alg_values_supported":["RS256"],"issuer":"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_4OqDoWVrZ","jwks_uri":"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_4OqDoWVrZ/.well-known/jwks.json","response_types_supported":["code","token"],"scopes_supported":["openid","email","phone","profile"],"subject_types_supported":["public"],"token_endpoint":"https://auth-groovycalamari.auth.us-east-1.amazoncognito.com/oauth2/token","token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"userinfo_endpoint":"https://auth-groovycalamari.auth.us-east-1.amazoncognito.com/oauth2/userInfo"}'
        }

    }
}
