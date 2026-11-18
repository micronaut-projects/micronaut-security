package io.micronaut.security.aot;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.squareup.javapoet.JavaFile;
import com.sun.net.httpserver.HttpServer;
import io.micronaut.aot.core.config.DefaultConfiguration;
import io.micronaut.aot.core.context.ApplicationContextAnalyzer;
import io.micronaut.aot.core.context.DefaultSourceGenerationContext;
import io.micronaut.context.env.Environment;
import io.micronaut.core.optim.StaticOptimizations;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link JwksFetcherCodeGenerator} bakes the JWKS fetched at build time into a thread-safe map, since the JWKS of a
 * url may be discarded at runtime while other threads read it.
 */
class JwksFetcherCodeGeneratorTest {

    private static final String PACKAGE_NAME = "io.micronaut.test";
    private static final String KEY_ID = "aot";

    private static HttpServer jwksServer;
    private static String jwksUrl;

    @BeforeAll
    static void startJwksServer() throws Exception {
        byte[] jwks = new JWKSet(new RSAKeyGenerator(2048)
                .keyID(KEY_ID)
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .generate()
                .toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
        jwksServer = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        jwksServer.createContext("/keys", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, jwks.length);
            exchange.getResponseBody().write(jwks);
            exchange.close();
        });
        jwksServer.start();
        jwksUrl = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":" + jwksServer.getAddress().getPort() + "/keys";
    }

    @AfterAll
    static void stopJwksServer() {
        jwksServer.stop(0);
    }

    @Test
    void jwksFetchedAtBuildTimeIsBakedIntoAThreadSafeMap(@TempDir Path outputDirectory) throws Exception {
        DefaultSourceGenerationContext context = generate(outputDirectory);

        assertTrue(context.getGeneratedStaticInitializers().isEmpty());
        String loader = source(context, "AotJwksFetcher");
        assertTrue(loader.contains("public class AotJwksFetcher implements StaticOptimizations.Loader<DefaultJwkSetFetcher.Optimizations>"), loader);
        assertTrue(loader.contains("Map<String, Supplier<JWKSet>> configs = new ConcurrentHashMap<String, Supplier<JWKSet>>();"), loader);
        assertTrue(loader.contains("configs.put(\"" + jwksUrl + "\", AotJwkSetFetcher0::create);"), loader);
        assertTrue(loader.contains("return new DefaultJwkSetFetcher.Optimizations(configs);"), loader);
        String jwkSet = source(context, "AotJwkSetFetcher0");
        assertTrue(jwkSet.contains("public static JWKSet create()"), jwkSet);
        assertTrue(jwkSet.contains("return JWKSet.parse("), jwkSet);
    }

    @Test
    void generatedSourcesCompileAndLoadTheJwksFetchedAtBuildTime(@TempDir Path outputDirectory) throws Exception {
        DefaultSourceGenerationContext context = generate(outputDirectory);
        Path classesDirectory = compile(context.getGeneratedJavaFiles(), outputDirectory.resolve("classes"));

        try (URLClassLoader classLoader = new URLClassLoader(new URL[] {classesDirectory.toUri().toURL()}, getClass().getClassLoader())) {
            @SuppressWarnings("unchecked")
            StaticOptimizations.Loader<DefaultJwkSetFetcher.Optimizations> loader = (StaticOptimizations.Loader<DefaultJwkSetFetcher.Optimizations>)
                    classLoader.loadClass(PACKAGE_NAME + ".AotJwksFetcher").getDeclaredConstructor().newInstance();
            DefaultJwkSetFetcher.Optimizations optimizations = loader.load();

            Supplier<JWKSet> jwkSet = optimizations.findJwkSet(jwksUrl).orElseThrow();
            assertNotNull(jwkSet.get().getKeyByKeyId(KEY_ID));

            optimizations.clear(jwksUrl);
            assertTrue(optimizations.findJwkSet(jwksUrl).isEmpty(), "the JWKS baked at build time is only an initial seed");
        }
    }

    private static DefaultSourceGenerationContext generate(Path outputDirectory) {
        ApplicationContextAnalyzer analyzer = ApplicationContextAnalyzer.create(builder -> builder
                .properties(Map.of("micronaut.security.token.jwt.signatures.jwks.foo.url", jwksUrl))
                .environments(Environment.TEST));
        try {
            DefaultSourceGenerationContext context = new DefaultSourceGenerationContext(PACKAGE_NAME, analyzer, new DefaultConfiguration(new Properties()), outputDirectory);
            new JwksFetcherCodeGenerator().generate(context);
            return context;
        } finally {
            analyzer.getApplicationContext().close();
        }
    }

    private static String source(DefaultSourceGenerationContext context, String simpleName) {
        List<JavaFile> matches = context.getGeneratedJavaFiles().stream()
                .filter(javaFile -> simpleName.equals(javaFile.typeSpec.name))
                .toList();
        assertEquals(1, matches.size(), () -> "expected one generated class named " + simpleName + " but got " + context.getGeneratedJavaFiles());
        return matches.get(0).toString();
    }

    private static Path compile(List<JavaFile> javaFiles, Path classesDirectory) throws Exception {
        Files.createDirectories(classesDirectory);
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        StringWriter output = new StringWriter();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            fileManager.setLocationFromPaths(StandardLocation.CLASS_OUTPUT, List.of(classesDirectory));
            List<JavaFileObject> sources = javaFiles.stream().map(JavaFile::toJavaFileObject).toList();
            boolean compiled = compiler.getTask(output, fileManager, null, List.of("-proc:none"), null, sources).call();
            assertTrue(compiled, () -> "generated sources do not compile: " + output);
        }
        return classesDirectory;
    }
}
