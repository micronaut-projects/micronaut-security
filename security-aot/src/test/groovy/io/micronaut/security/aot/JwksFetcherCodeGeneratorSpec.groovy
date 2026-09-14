//file:noinspection HardCodedStringLiteral
package io.micronaut.security.aot

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.micronaut.aot.core.AOTCodeGenerator
import io.micronaut.aot.core.codegen.AbstractSourceGeneratorSpec
import io.micronaut.context.ApplicationContext
import io.micronaut.context.ApplicationContextBuilder
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import spock.lang.AutoCleanup
import spock.lang.Shared

class JwksFetcherCodeGeneratorSpec extends AbstractSourceGeneratorSpec {

    static final String JWKS = new JWKSet(new RSAKeyGenerator(2048)
            .keyID('aot')
            .algorithm(JWSAlgorithm.RS256)
            .keyUse(KeyUse.SIGNATURE)
            .generate()
            .toPublicJWK()).toString()

    @AutoCleanup
    @Shared
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer,
            ['spec.name': 'EmbeddedServerJwksFetcherCodeGeneratorSpec'],
            Environment.TEST)

    /**
     * The base class builds the application context in {@code setup()}, before the feature body runs, so a
     * data-driven feature hands its properties over through the iteration's data variables.
     */
    @Override
    protected void customizeContext(ApplicationContextBuilder builder) {
        Map<String, Object> contextProperties = specificationContext.currentIteration.dataVariables['contextProperties'] as Map<String, Object>
        builder = builder.properties(contextProperties ?: [
                'micronaut.security.token.jwt.signatures.jwks.foo.url': keysUrl,
        ])
        builder.environments(Environment.TEST)
        super.customizeContext(builder)
    }

    @Override
    AOTCodeGenerator newGenerator() {
        return new JwksFetcherCodeGenerator()
    }

    String getKeysUrl() {
        "http://localhost:$embeddedServer.port/keys".toString()
    }

    String getOtherKeysUrl() {
        "http://localhost:$embeddedServer.port/other-keys".toString()
    }

    void "verify JwksFetcherCodeGenerator seeds a thread-safe map with the JWKS fetched at build time"() {
        expect:
        embeddedServer.applicationContext.containsBean(KeysController)

        when:
        generate()

        then:
        assertThatGeneratedSources {
            doesNotCreateInitializer()
            hasClass("AotJwksFetcher") {
                withSources """package io.micronaut.test;

import com.nimbusds.jose.jwk.JWKSet;
import io.micronaut.core.optim.StaticOptimizations;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher;
import java.lang.Override;
import java.lang.String;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

public class AotJwksFetcher implements StaticOptimizations.Loader<DefaultJwkSetFetcher.Optimizations> {
  @Override
  public DefaultJwkSetFetcher.Optimizations load() {
    Map<String, Supplier<JWKSet>> configs = new ConcurrentHashMap<String, Supplier<JWKSet>>();
    configs.put("http://localhost:${embeddedServer.port}/keys", AotJwkSetFetcher0::create);
    return new DefaultJwkSetFetcher.Optimizations(configs);
  }
}"""
                containingSources 'new ConcurrentHashMap<String, Supplier<JWKSet>>()'
            }
            hasClass("AotJwkSetFetcher0") {
                containingSources 'public static JWKSet create()'
                containingSources 'return JWKSet.parse('
            }
            compiles()
        }
    }

    void "a JwksSignatureConfiguration and an OpenID provider sharing a name but pointing at different URLs are both baked"() {
        when:
        generate()

        then:
        assertThatGeneratedSources {
            doesNotCreateInitializer()
            assert generatedClasses.size() == 3
            hasClass("AotJwksFetcher") {
                containingSources "configs.put(\"${keysUrl}\", "
                containingSources "configs.put(\"${otherKeysUrl}\", "
            }
            hasClass("AotJwkSetFetcher0") {
                containingSources 'public static JWKSet create()'
            }
            hasClass("AotJwkSetFetcher1") {
                containingSources 'public static JWKSet create()'
            }
            compiles()
        }

        where:
        contextProperties << [[
                'micronaut.security.token.jwt.signatures.jwks.x.url'       : keysUrl,
                'micronaut.security.oauth2.clients.x.client-id'            : 'XXX',
                'micronaut.security.oauth2.clients.x.client-secret'        : 'YYY',
                'micronaut.security.oauth2.clients.x.openid.fetch-configuration': false,
                'micronaut.security.oauth2.clients.x.openid.jwks-uri'      : otherKeysUrl,
        ]]
    }

    void "a JWKS URL shared by a JwksSignatureConfiguration and an OpenID provider is baked only once"() {
        when:
        generate()

        then:
        assertThatGeneratedSources {
            doesNotCreateInitializer()
            assert generatedClasses.size() == 2
            hasClass("AotJwksFetcher") {
                withSources """package io.micronaut.test;

import com.nimbusds.jose.jwk.JWKSet;
import io.micronaut.core.optim.StaticOptimizations;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher;
import java.lang.Override;
import java.lang.String;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

public class AotJwksFetcher implements StaticOptimizations.Loader<DefaultJwkSetFetcher.Optimizations> {
  @Override
  public DefaultJwkSetFetcher.Optimizations load() {
    Map<String, Supplier<JWKSet>> configs = new ConcurrentHashMap<String, Supplier<JWKSet>>();
    configs.put("${keysUrl}", AotJwkSetFetcher0::create);
    return new DefaultJwkSetFetcher.Optimizations(configs);
  }
}"""
            }
            hasClass("AotJwkSetFetcher0") {
                containingSources 'public static JWKSet create()'
            }
            compiles()
        }

        where:
        contextProperties << [[
                'micronaut.security.token.jwt.signatures.jwks.x.url'       : keysUrl,
                'micronaut.security.oauth2.clients.y.client-id'            : 'XXX',
                'micronaut.security.oauth2.clients.y.client-secret'        : 'YYY',
                'micronaut.security.oauth2.clients.y.openid.fetch-configuration': false,
                'micronaut.security.oauth2.clients.y.openid.jwks-uri'      : keysUrl,
        ]]
    }

    @Requires(property = 'spec.name', value = 'EmbeddedServerJwksFetcherCodeGeneratorSpec')
    @Controller
    static class KeysController {

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/keys")
        @Secured(SecurityRule.IS_ANONYMOUS)
        String index() {
            JWKS
        }

        @Produces(MediaType.APPLICATION_JSON)
        @Get("/other-keys")
        @Secured(SecurityRule.IS_ANONYMOUS)
        String otherKeys() {
            JWKS
        }
    }
}
