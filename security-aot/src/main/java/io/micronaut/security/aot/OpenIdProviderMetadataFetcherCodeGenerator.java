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
import io.micronaut.context.Qualifier;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.optim.StaticOptimizations;
import io.micronaut.core.util.StringUtils;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;

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
 * @since 3.3.0
 */
@AOTModule(id = OpenIdProviderMetadataFetcherCodeGenerator.SECURITY_AOT_MODULE_ID)
public class OpenIdProviderMetadataFetcherCodeGenerator extends AbstractCodeGenerator { //TODO renames this class
    /**
     * AOT Module ID.
     */
    public static final String SECURITY_AOT_MODULE_ID = "micronaut.security.openid-configuration";
    private static final ParameterizedTypeName SUPPLIER_OF_METADATA = ParameterizedTypeName.get(Supplier.class, DefaultOpenIdProviderMetadata.class);

    @Override
    public void generate(@NonNull AOTContext context) {
        List<GeneratedFile> files = generateJavaFiles(context);
        if (!files.isEmpty()) {
            context.registerStaticInitializer(staticMethod("preloadOpenIdMetadata", body -> {
                body.addStatement("$T configs = new $T()",
                        ParameterizedTypeName.get(ClassName.get(Map.class), TypeName.get(String.class), SUPPLIER_OF_METADATA),
                        ParameterizedTypeName.get(ClassName.get(HashMap.class), TypeName.get(String.class), SUPPLIER_OF_METADATA)
                );
                for (GeneratedFile f : files) {
                    context.registerGeneratedSourceFile(f.getJavaFile());
                    body.addStatement("context.put($S, $T::create)", f.getName(), ClassName.bestGuess(f.getSimpleName()));
                }
                body.addStatement("$T.set($T, configs)", StaticOptimizations.class, DefaultOpenIdProviderMetadataFetcher.Optimizations.class);
            }));
        }
    }

    private List<GeneratedFile> generateJavaFiles(@NonNull AOTContext context) {
        ApplicationContext ctx = context.getAnalyzer()
                .getApplicationContext();
        Collection<OpenIdClientConfiguration> clientConfigurations = ctx
                .getBeansOfType(OpenIdClientConfiguration.class);

        List<GeneratedFile> files = new ArrayList<>();
        for (OpenIdClientConfiguration clientConfig : clientConfigurations) {
            final Qualifier<OpenIdProviderMetadataFetcher> nameQualifier = Qualifiers.byName(clientConfig.getName());
            if (clientConfig.getIssuer().isPresent() && ctx.containsBean(OpenIdProviderMetadataFetcher.class, nameQualifier)) {
                OpenIdProviderMetadataFetcher fetcher = ctx.getBean(OpenIdProviderMetadataFetcher.class, nameQualifier);
                DefaultOpenIdProviderMetadata defaultOpenIdProviderMetadata = fetcher.fetch();
                final String simpleName = generatedClassSimpleName(clientConfig);
                files.add(new GeneratedFile(clientConfig.getName(),
                        simpleName,
                        generateJavaFile(context, simpleName, defaultOpenIdProviderMetadata)));
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
                .addStatement("$T metadata = new $T()", DefaultOpenIdProviderMetadata.class, DefaultOpenIdProviderMetadata.class);
        addStringSetterStatement(methodBuilder, "setUserinfoEndpoint", defaultOpenIdProviderMetadata.getUserinfoEndpoint());
        addBooleanSetterStatement(methodBuilder, "setRequireRequestUriRegistration", defaultOpenIdProviderMetadata.getRequireRequestUriRegistration());
        addStringSetterStatement(methodBuilder, "setAuthorizationEndpoint", defaultOpenIdProviderMetadata.getAuthorizationEndpoint());
        addListStringSetterStatement(methodBuilder, "userinfoEncryptionEncValuesSupported", "setUserinfoEncryptionEncValuesSupported", defaultOpenIdProviderMetadata.getUserinfoEncryptionEncValuesSupported());
        addListStringSetterStatement(methodBuilder, "idTokenEncryptionEncValuesSupported", "setIdTokenEncryptionEncValuesSupported", defaultOpenIdProviderMetadata.getIdTokenEncryptionEncValuesSupported());
        addListStringSetterStatement(methodBuilder, "userinfoEncryptionAlgValuesSupported", "setUserinfoEncryptionAlgValuesSupported", defaultOpenIdProviderMetadata.getUserInfoEncryptionAlgValuesSupported());
        addListStringSetterStatement(methodBuilder, "idTokenSigningAlgValuesSupported", "setIdTokenSigningAlgValuesSupported", defaultOpenIdProviderMetadata.getIdTokenSigningAlgValuesSupported());
        addStringSetterStatement(methodBuilder, "setIssuer", defaultOpenIdProviderMetadata.getIssuer());
        addStringSetterStatement(methodBuilder, "setJwksUri", defaultOpenIdProviderMetadata.getJwksUri());
        addListStringSetterStatement(methodBuilder, "responseTypesSupported", "setResponseTypesSupported", defaultOpenIdProviderMetadata.getResponseTypesSupported());
        addListStringSetterStatement(methodBuilder, "scopesSupported", "setScopesSupported", defaultOpenIdProviderMetadata.getScopesSupported());
        addListStringSetterStatement(methodBuilder, "subjectTypesSupported", "setSubjectTypesSupported", defaultOpenIdProviderMetadata.getSubjectTypesSupported());
        addStringSetterStatement(methodBuilder, "setTokenEndpoint", defaultOpenIdProviderMetadata.getTokenEndpoint());
        addListStringSetterStatement(methodBuilder, "tokenEndpointAuthSigningAlgValuesSupported", "setTokenEndpointAuthSigningAlgValuesSupported", defaultOpenIdProviderMetadata.getTokenEndpointAuthSigningAlgValuesSupported());
        addListStringSetterStatement(methodBuilder, "displayValuesSupported", "setDisplayValuesSupported", defaultOpenIdProviderMetadata.getDisplayValuesSupported());
        addListStringSetterStatement(methodBuilder, "claimTypesSupported", "setClaimTypesSupported", defaultOpenIdProviderMetadata.getClaimTypesSupported());
        addListStringSetterStatement(methodBuilder, "tokenEndpointAuthMethodsSupported", "setTokenEndpointAuthMethodsSupported", defaultOpenIdProviderMetadata.getTokenEndpointAuthMethodsSupported());
        addListStringSetterStatement(methodBuilder, "responseModesSupported", "setResponseModesSupported", defaultOpenIdProviderMetadata.getResponseModesSupported());
        addListStringSetterStatement(methodBuilder, "acrValuesSupported", "setAcrValuesSupported", defaultOpenIdProviderMetadata.getAcrValuesSupported());
        addListStringSetterStatement(methodBuilder, "grantTypesSupported", "setGrantTypesSupported", defaultOpenIdProviderMetadata.getGrantTypesSupported());
        addStringSetterStatement(methodBuilder, "setRegistrationEndpoint", defaultOpenIdProviderMetadata.getRegistrationEndpoint());
        addStringSetterStatement(methodBuilder, "setServiceDocumentation", defaultOpenIdProviderMetadata.getServiceDocumentation());
        addListStringSetterStatement(methodBuilder, "claimsLocalesSupported", "setClaimsLocalesSupported", defaultOpenIdProviderMetadata.getClaimsLocalesSupported());
        addListStringSetterStatement(methodBuilder, "uriLocalesSupported", "setUriLocalesSupported", defaultOpenIdProviderMetadata.getUriLocalesSupported());
        addBooleanSetterStatement(methodBuilder, "setClaimsParameterSupported", defaultOpenIdProviderMetadata.getClaimsParameterSupported());
        addListStringSetterStatement(methodBuilder, "claimsSupported", "setClaimsSupported", defaultOpenIdProviderMetadata.getClaimsSupported());
        addListStringSetterStatement(methodBuilder, "codeChallengeMethodsSupported", "setCodeChallengeMethodsSupported", defaultOpenIdProviderMetadata.getCodeChallengeMethodsSupported());
        addStringSetterStatement(methodBuilder, "setIntrospectionEndpoint", defaultOpenIdProviderMetadata.getIntrospectionEndpoint());
        addListStringSetterStatement(methodBuilder, "introspectionEndpointAuthMethodsSupported", "setIntrospectionEndpointAuthMethodsSupported", defaultOpenIdProviderMetadata.getIntrospectionEndpointAuthMethodsSupported());
        addStringSetterStatement(methodBuilder, "setRevocationEndpoint", defaultOpenIdProviderMetadata.getRevocationEndpoint());
        addListStringSetterStatement(methodBuilder, "revocationEndpointAuthMethodsSupported", "setRevocationEndpointAuthMethodsSupported", defaultOpenIdProviderMetadata.getRevocationEndpointAuthMethodsSupported());
        addStringSetterStatement(methodBuilder, "setCheckSessionIframe", defaultOpenIdProviderMetadata.getCheckSessionIframe());
        addStringSetterStatement(methodBuilder, "setEndSessionEndpoint", defaultOpenIdProviderMetadata.getEndSessionEndpoint());
        addBooleanSetterStatement(methodBuilder, "setRequestUriParameterSupported", defaultOpenIdProviderMetadata.getRequestUriParameterSupported());
        addStringSetterStatement(methodBuilder, "setOpPolicyUri", defaultOpenIdProviderMetadata.getOpPolicyUri());
        addStringSetterStatement(methodBuilder, "setOpTosUri", defaultOpenIdProviderMetadata.getOpTosUri());
        addBooleanSetterStatement(methodBuilder, "setRequestParameterSupported", defaultOpenIdProviderMetadata.getRequestParameterSupported());
        addListStringSetterStatement(methodBuilder, "requestObjectEncryptionAlgValuesSupported", "setRequestObjectEncryptionAlgValuesSupported", defaultOpenIdProviderMetadata.getRequestObjectEncryptionAlgValuesSupported());
        addListStringSetterStatement(methodBuilder, "requestObjectEncryptionEncValuesSupported", "setRequestObjectEncryptionEncValuesSupported", defaultOpenIdProviderMetadata.getRequestObjectEncryptionEncValuesSupported());
        addListStringSetterStatement(methodBuilder, "requestObjectSigningAlgValuesSupported", "setRequestObjectSigningAlgValuesSupported", defaultOpenIdProviderMetadata.getRequestObjectSigningAlgValuesSupported());
        return methodBuilder.addStatement("return metadata").build();
    }

    private void addStringSetterStatement(@NonNull MethodSpec.Builder methodBuilder,
                                          @NonNull String setter,
                                          @Nullable String value) {
        if (value != null) {
            methodBuilder.addStatement("metadata." + setter + "($S)", value);
        }
    }

    private void addBooleanSetterStatement(@NonNull MethodSpec.Builder methodBuilder,
                                           @NonNull String setter,
                                           @Nullable Boolean value) {
        if (value != null) {
            methodBuilder.addStatement("metadata." + setter + "($L)", value);
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
            methodBuilder.addStatement("metadata." + setter + "(" + listVariableName + ")");
        }
    }
}
