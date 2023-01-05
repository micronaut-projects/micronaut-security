//file:noinspection HardCodedStringLiteral
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
            doesNotCreateInitializer()
            hasClass("AotOpenIdProviderMetadataFetcherCode") {
                withSources """package io.micronaut.test;

import io.micronaut.core.optim.StaticOptimizations;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadataFetcher;
import java.lang.Override;
import java.lang.String;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

public class AotOpenIdProviderMetadataFetcherCode implements StaticOptimizations.Loader<DefaultOpenIdProviderMetadataFetcher.Optimizations> {
  @Override
  public DefaultOpenIdProviderMetadataFetcher.Optimizations load() {
    Map<String, Supplier<DefaultOpenIdProviderMetadata>> configs = new HashMap<String, Supplier<DefaultOpenIdProviderMetadata>>();
    configs.put("cognito", AotOpenIdProviderMetadataFetcherCognito::create);
    return new DefaultOpenIdProviderMetadataFetcher.Optimizations(configs);
  }
}"""
            }
            hasClass("AotOpenIdProviderMetadataFetcherCognito") {
                withSources """package io.micronaut.test;

import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import java.lang.String;
import java.util.ArrayList;
import java.util.List;

public class AotOpenIdProviderMetadataFetcherCognito {
  public static DefaultOpenIdProviderMetadata create() {
    DefaultOpenIdProviderMetadata metadata = new DefaultOpenIdProviderMetadata();
    metadata.setUserinfoEndpoint("https://auth-groovycalamari.auth.us-east-1.amazoncognito.com/oauth2/userInfo");
    metadata.setAuthorizationEndpoint("https://auth-groovycalamari.auth.us-east-1.amazoncognito.com/oauth2/authorize");
    List<String> idTokenSigningAlgValuesSupported = new ArrayList<>();
    idTokenSigningAlgValuesSupported.add("RS256");
    metadata.setIdTokenSigningAlgValuesSupported(idTokenSigningAlgValuesSupported);
    metadata.setIssuer("https://cognito-idp.us-east-1.amazonaws.com/us-east-1_4OqDoWVrZ");
    metadata.setJwksUri("https://cognito-idp.us-east-1.amazonaws.com/us-east-1_4OqDoWVrZ/.well-known/jwks.json");
    List<String> responseTypesSupported = new ArrayList<>();
    responseTypesSupported.add("code");
    responseTypesSupported.add("token");
    metadata.setResponseTypesSupported(responseTypesSupported);
    List<String> scopesSupported = new ArrayList<>();
    scopesSupported.add("openid");
    scopesSupported.add("email");
    scopesSupported.add("phone");
    scopesSupported.add("profile");
    metadata.setScopesSupported(scopesSupported);
    List<String> subjectTypesSupported = new ArrayList<>();
    subjectTypesSupported.add("public");
    metadata.setSubjectTypesSupported(subjectTypesSupported);
    metadata.setTokenEndpoint("https://auth-groovycalamari.auth.us-east-1.amazoncognito.com/oauth2/token");
    List<String> tokenEndpointAuthMethodsSupported = new ArrayList<>();
    tokenEndpointAuthMethodsSupported.add("client_secret_basic");
    tokenEndpointAuthMethodsSupported.add("client_secret_post");
    metadata.setTokenEndpointAuthMethodsSupported(tokenEndpointAuthMethodsSupported);
    metadata.setClaimsParameterSupported(false);
    return metadata;
  }
}"""
                compiles()
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
