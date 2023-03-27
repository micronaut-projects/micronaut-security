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

import com.squareup.javapoet.ClassName;
import com.squareup.javapoet.JavaFile;
import com.squareup.javapoet.MethodSpec;
import com.squareup.javapoet.ParameterizedTypeName;
import com.squareup.javapoet.TypeName;
import com.squareup.javapoet.TypeSpec;
import io.micronaut.aot.core.AOTContext;
import io.micronaut.aot.core.AOTModule;
import io.micronaut.aot.core.codegen.AbstractCodeGenerator;
import io.micronaut.context.Qualifier;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.lang.model.element.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Optimization to fetch OpenID Configuration at build time.
 * @author Sergio del Amo
 * @since 3.9.0
 */
@AOTModule(id = OpenIdProviderMetadataFetcherCodeGenerator.SECURITY_AOT_OPENID_CONFIGURATION_MODULE_ID)
public class OpenIdProviderMetadataFetcherCodeGenerator extends AbstractCodeGenerator {
    /**
     * AOT Module ID.
     */
    public static final String SECURITY_AOT_OPENID_CONFIGURATION_MODULE_ID = "micronaut.security.openid-configuration";
    private static final Logger LOG = LoggerFactory.getLogger(OpenIdProviderMetadataFetcherCodeGenerator.class);
    private static final ParameterizedTypeName SUPPLIER_OF_METADATA = ParameterizedTypeName.get(Supplier.class, DefaultOpenIdProviderMetadata.class);
    private static final String BUILDER = "builder.";

    @Override
    public void generate(@NonNull AOTContext context) {
        List<GeneratedFile> files = generateJavaFiles(context);
        if (!files.isEmpty()) {
            context.registerStaticOptimization("AotOpenIdProviderMetadataFetcherCode", DefaultOpenIdProviderMetadataFetcher.Optimizations.class, body -> {
                body.addStatement("$T configs = new $T()",
                        ParameterizedTypeName.get(ClassName.get(Map.class), TypeName.get(String.class), SUPPLIER_OF_METADATA),
                        ParameterizedTypeName.get(ClassName.get(HashMap.class), TypeName.get(String.class), SUPPLIER_OF_METADATA)
                );
                for (GeneratedFile f : files) {
                    context.registerGeneratedSourceFile(f.getJavaFile());
                    body.addStatement("configs.put($S, $T::create)", f.getName(), ClassName.bestGuess(f.getSimpleName()));
                }
                body.addStatement("return new $T(configs)", DefaultOpenIdProviderMetadataFetcher.Optimizations.class);
            });
        }
    }

    private List<GeneratedFile> generateJavaFiles(@NonNull AOTContext context) {
        Collection<OpenIdClientConfiguration> clientConfigurations = AOTContextUtils.getBeansOfType(OpenIdClientConfiguration.class, context);

        List<GeneratedFile> files = new ArrayList<>();
        for (OpenIdClientConfiguration clientConfig : clientConfigurations) {
            final Qualifier<OpenIdProviderMetadataFetcher> nameQualifier = Qualifiers.byName(clientConfig.getName());
            if (clientConfig.getIssuer().isPresent() && AOTContextUtils.containsBean(OpenIdProviderMetadataFetcher.class, nameQualifier, context)) {
                OpenIdProviderMetadataFetcher fetcher = AOTContextUtils.getBean(OpenIdProviderMetadataFetcher.class, nameQualifier, context);
                try {
                    DefaultOpenIdProviderMetadata defaultOpenIdProviderMetadata = fetcher.fetch();
                    final String simpleName = generatedClassSimpleName(clientConfig);
                    files.add(new GeneratedFile(clientConfig.getName(),
                        simpleName,
                        generateJavaFile(context, simpleName, defaultOpenIdProviderMetadata)));
                } catch (Exception e) {
                    LOG.error("Could not generate {} optimizations for OAuth 2.0 Client with qualifier {}", SECURITY_AOT_OPENID_CONFIGURATION_MODULE_ID, nameQualifier);
                }
            }
        }
        return files;
    }

    private String generatedClassSimpleName(@NonNull OpenIdClientConfiguration clientConfig) {
        return "Aot" + OpenIdProviderMetadataFetcher.class.getSimpleName() + StringUtils.capitalize(clientConfig.getName());
    }

    private JavaFile generateJavaFile(@NonNull AOTContext context,
                                      @NonNull String fileSimpleName,
                                      @NonNull DefaultOpenIdProviderMetadata defaultOpenIdProviderMetadata) {
        return context.javaFile(TypeSpec.classBuilder(fileSimpleName)
                .addModifiers(Modifier.PUBLIC)
                .addMethod(generateMethod(defaultOpenIdProviderMetadata))
                .build());
    }

    private MethodSpec generateMethod(@NonNull DefaultOpenIdProviderMetadata defaultOpenIdProviderMetadata) {
        MethodSpec.Builder methodBuilder = MethodSpec.methodBuilder("create")
                .returns(DefaultOpenIdProviderMetadata.class)
                .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                .addStatement("$T builder = $T.builder()", DefaultOpenIdProviderMetadata.Builder.class, DefaultOpenIdProviderMetadata.class);
        addStringSetterStatement(methodBuilder, "userinfoEndpoint", defaultOpenIdProviderMetadata.getUserinfoEndpoint());
        addBooleanSetterStatement(methodBuilder, "requireRequestUriRegistration", defaultOpenIdProviderMetadata.getRequireRequestUriRegistration());
        addStringSetterStatement(methodBuilder, "authorizationEndpoint", defaultOpenIdProviderMetadata.getAuthorizationEndpoint());
        addListStringSetterStatement(methodBuilder, "userinfoEncryptionEncValuesSupported", "userinfoEncryptionEncValuesSupported", defaultOpenIdProviderMetadata.getUserinfoEncryptionEncValuesSupported());
        addListStringSetterStatement(methodBuilder, "idTokenEncryptionEncValuesSupported", "idTokenEncryptionEncValuesSupported", defaultOpenIdProviderMetadata.getIdTokenEncryptionEncValuesSupported());
        addListStringSetterStatement(methodBuilder, "userinfoEncryptionAlgValuesSupported", "userinfoEncryptionAlgValuesSupported", defaultOpenIdProviderMetadata.getUserInfoEncryptionAlgValuesSupported());
        addListStringSetterStatement(methodBuilder, "idTokenSigningAlgValuesSupported", "idTokenSigningAlgValuesSupported", defaultOpenIdProviderMetadata.getIdTokenSigningAlgValuesSupported());
        addStringSetterStatement(methodBuilder, "issuer", defaultOpenIdProviderMetadata.getIssuer());
        addStringSetterStatement(methodBuilder, "jwksUri", defaultOpenIdProviderMetadata.getJwksUri());
        addListStringSetterStatement(methodBuilder, "responseTypesSupported", "responseTypesSupported", defaultOpenIdProviderMetadata.getResponseTypesSupported());
        addListStringSetterStatement(methodBuilder, "scopesSupported", "scopesSupported", defaultOpenIdProviderMetadata.getScopesSupported());
        addListStringSetterStatement(methodBuilder, "subjectTypesSupported", "subjectTypesSupported", defaultOpenIdProviderMetadata.getSubjectTypesSupported());
        addStringSetterStatement(methodBuilder, "tokenEndpoint", defaultOpenIdProviderMetadata.getTokenEndpoint());
        addListStringSetterStatement(methodBuilder, "tokenEndpointAuthSigningAlgValuesSupported", "tokenEndpointAuthSigningAlgValuesSupported", defaultOpenIdProviderMetadata.getTokenEndpointAuthSigningAlgValuesSupported());
        addListStringSetterStatement(methodBuilder, "displayValuesSupported", "displayValuesSupported", defaultOpenIdProviderMetadata.getDisplayValuesSupported());
        addListStringSetterStatement(methodBuilder, "claimTypesSupported", "claimTypesSupported", defaultOpenIdProviderMetadata.getClaimTypesSupported());
        addListStringSetterStatement(methodBuilder, "tokenEndpointAuthMethodsSupported", "tokenEndpointAuthMethodsSupported", defaultOpenIdProviderMetadata.getTokenEndpointAuthMethodsSupported());
        addListStringSetterStatement(methodBuilder, "responseModesSupported", "responseModesSupported", defaultOpenIdProviderMetadata.getResponseModesSupported());
        addListStringSetterStatement(methodBuilder, "acrValuesSupported", "acrValuesSupported", defaultOpenIdProviderMetadata.getAcrValuesSupported());
        addListStringSetterStatement(methodBuilder, "grantTypesSupported", "grantTypesSupported", defaultOpenIdProviderMetadata.getGrantTypesSupported());
        addStringSetterStatement(methodBuilder, "registrationEndpoint", defaultOpenIdProviderMetadata.getRegistrationEndpoint());
        addStringSetterStatement(methodBuilder, "serviceDocumentation", defaultOpenIdProviderMetadata.getServiceDocumentation());
        addListStringSetterStatement(methodBuilder, "claimsLocalesSupported", "claimsLocalesSupported", defaultOpenIdProviderMetadata.getClaimsLocalesSupported());
        addListStringSetterStatement(methodBuilder, "uriLocalesSupported", "uriLocalesSupported", defaultOpenIdProviderMetadata.getUriLocalesSupported());
        addBooleanSetterStatement(methodBuilder, "claimsParameterSupported", defaultOpenIdProviderMetadata.getClaimsParameterSupported());
        addListStringSetterStatement(methodBuilder, "claimsSupported", "claimsSupported", defaultOpenIdProviderMetadata.getClaimsSupported());
        addListStringSetterStatement(methodBuilder, "codeChallengeMethodsSupported", "codeChallengeMethodsSupported", defaultOpenIdProviderMetadata.getCodeChallengeMethodsSupported());
        addStringSetterStatement(methodBuilder, "introspectionEndpoint", defaultOpenIdProviderMetadata.getIntrospectionEndpoint());
        addListStringSetterStatement(methodBuilder, "introspectionEndpointAuthMethodsSupported", "introspectionEndpointAuthMethodsSupported", defaultOpenIdProviderMetadata.getIntrospectionEndpointAuthMethodsSupported());
        addStringSetterStatement(methodBuilder, "revocationEndpoint", defaultOpenIdProviderMetadata.getRevocationEndpoint());
        addListStringSetterStatement(methodBuilder, "revocationEndpointAuthMethodsSupported", "revocationEndpointAuthMethodsSupported", defaultOpenIdProviderMetadata.getRevocationEndpointAuthMethodsSupported());
        addStringSetterStatement(methodBuilder, "checkSessionIframe", defaultOpenIdProviderMetadata.getCheckSessionIframe());
        addStringSetterStatement(methodBuilder, "endSessionEndpoint", defaultOpenIdProviderMetadata.getEndSessionEndpoint());
        addBooleanSetterStatement(methodBuilder, "requestUriParameterSupported", defaultOpenIdProviderMetadata.getRequestUriParameterSupported());
        addStringSetterStatement(methodBuilder, "opPolicyUri", defaultOpenIdProviderMetadata.getOpPolicyUri());
        addStringSetterStatement(methodBuilder, "opTosUri", defaultOpenIdProviderMetadata.getOpTosUri());
        addBooleanSetterStatement(methodBuilder, "requestParameterSupported", defaultOpenIdProviderMetadata.getRequestParameterSupported());
        addListStringSetterStatement(methodBuilder, "requestObjectEncryptionAlgValuesSupported", "requestObjectEncryptionAlgValuesSupported", defaultOpenIdProviderMetadata.getRequestObjectEncryptionAlgValuesSupported());
        addListStringSetterStatement(methodBuilder, "requestObjectEncryptionEncValuesSupported", "requestObjectEncryptionEncValuesSupported", defaultOpenIdProviderMetadata.getRequestObjectEncryptionEncValuesSupported());
        addListStringSetterStatement(methodBuilder, "requestObjectSigningAlgValuesSupported", "requestObjectSigningAlgValuesSupported", defaultOpenIdProviderMetadata.getRequestObjectSigningAlgValuesSupported());
        return methodBuilder.addStatement("return builder.build()").build();
    }

    private void addStringSetterStatement(@NonNull MethodSpec.Builder methodBuilder,
                                          @NonNull String setter,
                                          @Nullable String value) {
        if (value != null) {
            methodBuilder.addStatement(BUILDER + setter + "($S)", value);
        }
    }

    private void addBooleanSetterStatement(@NonNull MethodSpec.Builder methodBuilder,
                                           @NonNull String setter,
                                           @Nullable Boolean value) {
        if (value != null) {
            methodBuilder.addStatement(BUILDER + setter + "($L)", value);
        }
    }

    private void addListStringSetterStatement(@NonNull MethodSpec.Builder methodBuilder,
                                              @NonNull String listVariableName,
                                              @NonNull String setter,
                                              @Nullable List<String> values) {
        if (values != null) {
            methodBuilder.addStatement("$T<$T> " + listVariableName + " = new $T<>()", List.class, String.class, ArrayList.class);
            for (String value : values) {
                methodBuilder.addStatement(listVariableName + ".add($S)", value);
            }
            methodBuilder.addStatement(BUILDER + setter + "(" + listVariableName + ")");
        }
    }
}
