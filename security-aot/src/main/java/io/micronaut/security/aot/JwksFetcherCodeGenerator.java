/*
 * Copyright 2017-2023 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.aot;

import com.nimbusds.jose.jwk.JWKSet;
import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;
import com.squareup.javapoet.TypeSpec;
import io.micronaut.aot.core.AOTContext;
import io.micronaut.aot.core.AOTModule;
import io.micronaut.aot.core.codegen.AbstractCodeGenerator;
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwksClient;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import reactor.core.publisher.Mono;

import javax.lang.model.element.Modifier;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Optimization to fetch Json Web Key Set at build time.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@AOTModule(id = JwksFetcherCodeGenerator.SECURITY_AOT_JWKS_MODULE_ID)
public class JwksFetcherCodeGenerator extends AbstractCodeGenerator {
    /**
     * AOT Module ID.
     */
    public static final String SECURITY_AOT_JWKS_MODULE_ID = "micronaut.security.jwks";
    private static final ParameterizedTypeName SUPPLIER_OF_METADATA = ParameterizedTypeName.get(Supplier.class, JWKSet.class);

    @Override
    public void generate(@NonNull AOTContext context) {
        ApplicationContext applicationContext = context.getAnalyzer().getApplicationContext();
        if (!applicationContext.isRunning()) {
            applicationContext.start();
        }
        List<GeneratedFile> files = generateJavaFiles(context);
        if (!files.isEmpty()) {
            context.registerStaticOptimization("AotJwksFetcher", DefaultJwkSetFetcher.Optimizations.class, body -> {
                body.addStatement("$T configs = new $T()",
                        ParameterizedTypeName.get(ClassName.get(Map.class), TypeName.get(String.class), SUPPLIER_OF_METADATA),
                        ParameterizedTypeName.get(ClassName.get(HashMap.class), TypeName.get(String.class), SUPPLIER_OF_METADATA)
                );
                for (GeneratedFile generatedFile : files) {
                    context.registerGeneratedSourceFile(generatedFile.getJavaFile());
                    body.addStatement("configs.put($S, $T::create)", generatedFile.getName(), ClassName.bestGuess(generatedFile.getSimpleName()));
                }
                body.addStatement("return new $T(configs)", DefaultJwkSetFetcher.Optimizations.class);
            });
        }
    }

    @NonNull
    private Map<String, String> jwksUrls(@NonNull AOTContext context) {
        Map<String, String> urls = new HashMap<>();
        AOTContextUtils.getBeansOfType(JwksSignatureConfiguration.class, context)
            .forEach(config -> urls.put(config.getName(), config.getUrl()));
        AOTContextUtils.getBeansOfType(OpenIdProviderMetadata.class, context).stream()
            .filter(metadata -> metadata.getJwksUri() != null)
            .forEach(metadata -> urls.put(metadata.getName(), metadata.getJwksUri()));
        return urls;
    }

    private List<GeneratedFile> generateJavaFiles(@NonNull AOTContext context) {
        Map<String, String> urls = jwksUrls(context);
        JwksClient jwksClient = AOTContextUtils.getBean(JwksClient.class, context);
        List<GeneratedFile> result = new ArrayList<>();
        int count = 0;
        for (Map.Entry<String, String> entry: urls.entrySet()) {
            Optional<GeneratedFile> generatedFile = generatedFile(context, jwksClient, entry.getKey(), entry.getValue(), count);
            if (generatedFile.isPresent()) {
                result.add(generatedFile.get());
                count++;
            }
        }
        return result;
    }

    private Optional<GeneratedFile> generatedFile(AOTContext aotContext,
                                        JwksClient jwksClient,
                                        String providerName,
                                        String url,
                                        int count) {
        Optional<String> jwkSetOptional = Mono.from(jwksClient.load(providerName, url)).blockOptional();
        if (jwkSetOptional.isPresent()) {
            String json = jwkSetOptional.get();
            if (StringUtils.isNotEmpty(json)) {
                String simpleName = "Aot" + JwkSetFetcher.class.getSimpleName() + count;
                return Optional.of(new GeneratedFile(url, simpleName, generateJavaFile(aotContext, simpleName, json)));
            }
        }
        return Optional.empty();
    }

    private JavaFile generateJavaFile(@NonNull AOTContext context,
                                      @NonNull String fileSimpleName,
                                      @NonNull String json) {
        return context.javaFile(TypeSpec.classBuilder(fileSimpleName)
                .addModifiers(Modifier.PUBLIC)
                .addMethod(generateMethod(json))
                .build());
    }

    @NonNull
    private MethodSpec generateMethod(@NonNull String json) {
        return MethodSpec.methodBuilder("create")
                .returns(JWKSet.class)
                .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                .beginControlFlow("try")
                .addStatement("return JWKSet.parse($S)", json)
                .nextControlFlow("catch ($T e)", ParseException.class)
                .addStatement("throw new $T(e)", RuntimeException.class)
                .endControlFlow()
                .build();
    }
}
