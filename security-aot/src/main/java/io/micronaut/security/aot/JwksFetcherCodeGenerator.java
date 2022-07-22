/*
 * Copyright 2017-2021 original authors
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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;

import javax.lang.model.element.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Optimization to fetch Json Web Key Set at build time.
 * @author Sergio del Amo
 * @since 3.3.0
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
    private Set<String> jwksUrls(@NonNull AOTContext context) {
        Set<String> urls = new HashSet<>();
        AOTContextUtils.getBeansOfType(JwksSignatureConfiguration.class, context).stream()
            .map(JwksSignatureConfiguration::getUrl)
            .forEach(urls::add);
        AOTContextUtils.getBeansOfType(OpenIdProviderMetadata.class, context).stream()
            .map(OpenIdProviderMetadata::getJwksUri)
            .filter(Objects::nonNull)
            .forEach(urls::add);
        return urls;
    }

    private List<GeneratedFile> generateJavaFiles(@NonNull AOTContext context) {
        Set<String> urls = jwksUrls(context);
        JwkSetFetcher<?> jwkSetFetcher = AOTContextUtils.getBean(JwkSetFetcher.class, context);
        int count = 0;
        List<GeneratedFile> result = new ArrayList<>();
        for (String url : urls) {
            Optional<GeneratedFile> generatedFile = generatedFile(context, jwkSetFetcher, url, count);
            if (generatedFile.isPresent()) {
                result.add(generatedFile.get());
                count++;
            }
        }
        return result;
    }

    private Optional<GeneratedFile> generatedFile(AOTContext aotContext,
                                        JwkSetFetcher<?> jwkSetFetcher,
                                        String url,
                                        int count) {
        Optional<?> jwkSetOptional = jwkSetFetcher.fetch(url);
        if (jwkSetOptional.isPresent()) {
            Object obj = jwkSetOptional.get();
            if (obj instanceof JWKSet) {
                JWKSet jwkSet = (JWKSet) obj;
                String json = jwkSet.toString(false);
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
                .returns(DefaultOpenIdProviderMetadata.class)
                .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                .addStatement("return JWKSet.parse($S)", json)
                .build();
    }
}
