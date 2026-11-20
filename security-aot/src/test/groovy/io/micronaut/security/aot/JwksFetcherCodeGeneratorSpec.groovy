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
import io.micronaut.context.annotation.Property
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.context.env.Environment
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Produces
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.security.token.jwt.signature.jwks.JwksClient
import jakarta.inject.Singleton
import org.reactivestreams.Publisher
import reactor.core.publisher.Mono
import spock.lang.AutoCleanup
import spock.lang.Shared

class JwksFetcherCodeGeneratorSpec extends AbstractSourceGeneratorSpec {

    static final String JWKS = jwks('aot')

    static final String OTHER_JWKS = jwks('other')

    /**
     * The key ID as it appears in the generated Java string literal holding the JWKS.
     */
    static final String KID_AOT = /\"kid\":\"aot\"/

    static final String KID_OTHER = /\"kid\":\"other\"/

    private static String jwks(String keyId) {
        new JWKSet(new RSAKeyGenerator(2048)
                .keyID(keyId)
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .generate()
                .toPublicJWK()).toString()
    }

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

    /**
     * An OpenID client whose provider metadata is configured manually instead of being fetched from the provider.
     */
    private static Map<String, Object> openIdClient(String name, Map<String, Object> openIdProperties) {
        String prefix = "micronaut.security.oauth2.clients.${name}"
        Map<String, Object> properties = [
                ("${prefix}.client-id".toString())                 : 'XXX',
                ("${prefix}.client-secret".toString())             : 'YYY',
                ("${prefix}.openid.fetch-configuration".toString()): false,
        ]
        openIdProperties.each { key, value -> properties["${prefix}.openid.${key}".toString()] = value }
        properties
    }

    String getServerUrl() {
        "http://localhost:$embeddedServer.port".toString()
    }

    String getKeysUrl() {
        "$serverUrl/keys".toString()
    }

    String getOtherKeysUrl() {
        "$serverUrl/other-keys".toString()
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
                containingSources "configs.put(\"${keysUrl}\", AotJwkSetFetcher0::create);"
                containingSources "configs.put(\"${otherKeysUrl}\", AotJwkSetFetcher1::create);"
            }
            hasClass("AotJwkSetFetcher0") {
                containingSources KID_AOT
            }
            hasClass("AotJwkSetFetcher1") {
                containingSources KID_OTHER
            }
            compiles()
        }

        where:
        contextProperties << [[
                'micronaut.security.token.jwt.signatures.jwks.x.url'       : keysUrl,
        ] + openIdClient('x', ['jwks-uri': otherKeysUrl])]
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
        ] + openIdClient('y', ['jwks-uri': keysUrl])]
    }

    void "an OpenID provider without a JWKS URL is skipped"() {
        when:
        generate()

        then:
        assertThatGeneratedSources {
            doesNotCreateInitializer()
            assert generatedClasses.size() == 2
            hasClass("AotJwksFetcher") {
                containingSources "configs.put(\"${keysUrl}\", AotJwkSetFetcher0::create);"
            }
            hasClass("AotJwkSetFetcher0") {
                containingSources KID_AOT
            }
            compiles()
        }

        where:
        contextProperties << [[
                'micronaut.security.token.jwt.signatures.jwks.x.url'       : keysUrl,
        ] + openIdClient('y', ['authorization.url': 'https://idp.example.com/authorize'])]
    }

    void "a JWKS URL is baked by another source sharing it when the first source cannot retrieve the JWKS"() {
        when:
        generate()

        then:
        assertThatGeneratedSources {
            doesNotCreateInitializer()
            assert generatedClasses.size() == 2
            hasClass("AotJwksFetcher") {
                containingSources "configs.put(\"${keysUrl}\", AotJwkSetFetcher0::create);"
            }
            hasClass("AotJwkSetFetcher0") {
                containingSources 'public static JWKSet create()'
            }
            compiles()
        }

        where:
        contextProperties << [[
                'spec.unreachable-provider'                                : 'x',
                'micronaut.security.token.jwt.signatures.jwks.x.url'       : keysUrl,
        ] + openIdClient('y', ['jwks-uri': keysUrl])]
    }

    void "a relative JWKS URL declared by a single source is baked"() {
        when:
        generate()

        then:
        assertThatGeneratedSources {
            doesNotCreateInitializer()
            assert generatedClasses.size() == 2
            hasClass("AotJwksFetcher") {
                containingSources 'configs.put("/keys", AotJwkSetFetcher0::create);'
            }
            hasClass("AotJwkSetFetcher0") {
                containingSources 'public static JWKSet create()'
            }
            compiles()
        }

        where:
        contextProperties << [[
                'micronaut.http.services.x.url'                            : serverUrl,
                'micronaut.security.token.jwt.signatures.jwks.x.url'       : '/keys',
        ]]
    }

    void "a relative JWKS URL declared by several sources is not baked because each source may resolve it differently"() {
        when:
        generate()

        then:
        assertThatGeneratedSources {
            doesNotCreateInitializer()
            assert generatedClasses.empty
        }

        where:
        contextProperties << [[
                'micronaut.http.services.x.url'                            : serverUrl,
                'micronaut.http.services.y.url'                            : serverUrl,
                'micronaut.security.token.jwt.signatures.jwks.x.url'       : '/keys',
        ] + openIdClient('y', ['jwks-uri': '/keys'])]
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
            OTHER_JWKS
        }
    }

    /**
     * Simulates a provider whose HTTP client settings cannot reach the JWKS endpoint.
     */
    @Requires(property = 'spec.unreachable-provider')
    @Replaces(JwksClient)
    @Singleton
    static class UnreachableProviderJwksClient implements JwksClient {

        @Property(name = 'spec.unreachable-provider')
        String unreachableProvider

        @Override
        Publisher<String> load(String providerName, String url) {
            providerName == unreachableProvider ? Mono.<String>empty() : Mono.just(JWKS)
        }
    }
}
