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

        ApplicationContext ctx = context.getAnalyzer()
                .getApplicationContext();
        Collection<OpenIdClientConfiguration> clientConfigurations = ctx
                .getBeansOfType(OpenIdClientConfiguration.class);

        context.registerStaticInitializer(staticMethod("preloadOpenIdMetadata", body -> {
            body.addStatement("$T configs = new $T()",
                    ParameterizedTypeName.get(ClassName.get(Map.class), TypeName.get(String.class), SUPPLIER_OF_METADATA),
                    ParameterizedTypeName.get(ClassName.get(HashMap.class), TypeName.get(String.class), SUPPLIER_OF_METADATA)
            );
            for (OpenIdClientConfiguration clientConfig : clientConfigurations) {
                final Qualifier<OpenIdProviderMetadataFetcher> nameQualifier = Qualifiers.byName(clientConfig.getName());
                if (clientConfig.getIssuer().isPresent() && ctx.containsBean(OpenIdProviderMetadataFetcher.class, nameQualifier)) {
                    OpenIdProviderMetadataFetcher fetcher = ctx.getBean(OpenIdProviderMetadataFetcher.class, nameQualifier);
                    DefaultOpenIdProviderMetadata defaultOpenIdProviderMetadata = fetcher.fetch();
                    final String simpleName = generatedClassSimpleName(clientConfig);
                    context.registerGeneratedSourceFile(generateJavaFile(context, simpleName, defaultOpenIdProviderMetadata));
                    body.addStatement("context.put($S, $T::create)", clientConfig.getName(), ClassName.bestGuess(simpleName));
                }
            }
            body.addStatement("$T.set($T, configs)", StaticOptimizations.class, DefaultOpenIdProviderMetadataFetcher.Optimizations.class);
        }));
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
        if (defaultOpenIdProviderMetadata.getUserinfoEndpoint() != null) {
            methodBuilder.addStatement("metadata.setUserinfoEndpoint($S)", defaultOpenIdProviderMetadata.getUserinfoEndpoint());
        }
        if (defaultOpenIdProviderMetadata.getRequireRequestUriRegistration() != null) {
            methodBuilder.addStatement("metadata.setRequireRequestUriRegistration($S)", defaultOpenIdProviderMetadata.getRequireRequestUriRegistration());
        }
        if (defaultOpenIdProviderMetadata.getAuthorizationEndpoint() != null) {
            methodBuilder.addStatement("metadata.setAuthorizationEndpoint($S)", defaultOpenIdProviderMetadata.getAuthorizationEndpoint());
        }
        if (defaultOpenIdProviderMetadata.getUserinfoEncryptionEncValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "userinfoEncryptionEncValuesSupported", "setUserinfoEncryptionEncValuesSupported", defaultOpenIdProviderMetadata.getUserinfoEncryptionEncValuesSupported());
        }
        if (defaultOpenIdProviderMetadata.getIdTokenEncryptionEncValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "idTokenEncryptionEncValuesSupported", "setIdTokenEncryptionEncValuesSupported", defaultOpenIdProviderMetadata.getIdTokenEncryptionEncValuesSupported());
        }
        if (defaultOpenIdProviderMetadata.getUserInfoEncryptionAlgValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "userinfoEncryptionAlgValuesSupported", "setUserinfoEncryptionAlgValuesSupported", defaultOpenIdProviderMetadata.getUserInfoEncryptionAlgValuesSupported());
        }
        if (defaultOpenIdProviderMetadata.getIdTokenSigningAlgValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "idTokenSigningAlgValuesSupported", "setIdTokenSigningAlgValuesSupported", defaultOpenIdProviderMetadata.getIdTokenSigningAlgValuesSupported());
        }
        if (defaultOpenIdProviderMetadata.getIssuer() != null) {
            methodBuilder.addStatement("metadata.setIssuer($S)", defaultOpenIdProviderMetadata.getIssuer());
        }
        if (defaultOpenIdProviderMetadata.getJwksUri() != null) {
            methodBuilder.addStatement("metadata.setJwksUri($S)", defaultOpenIdProviderMetadata.getJwksUri());
        }
        if (defaultOpenIdProviderMetadata.getResponseTypesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "responseTypesSupported", "setResponseTypesSupported", defaultOpenIdProviderMetadata.getResponseTypesSupported());
        }
        if (defaultOpenIdProviderMetadata.getScopesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "scopesSupported", "setScopesSupported", defaultOpenIdProviderMetadata.getScopesSupported());
        }
        if (defaultOpenIdProviderMetadata.getSubjectTypesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "subjectTypesSupported", "setSubjectTypesSupported", defaultOpenIdProviderMetadata.getSubjectTypesSupported());
        }
        if (defaultOpenIdProviderMetadata.getTokenEndpoint() != null) {
            methodBuilder.addStatement("metadata.setTokenEndpoint($S)", defaultOpenIdProviderMetadata.getTokenEndpoint());
        }
        if (defaultOpenIdProviderMetadata.getTokenEndpointAuthSigningAlgValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "tokenEndpointAuthSigningAlgValuesSupported", "setTokenEndpointAuthSigningAlgValuesSupported", defaultOpenIdProviderMetadata.getTokenEndpointAuthSigningAlgValuesSupported());
        }
        if (defaultOpenIdProviderMetadata.getDisplayValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "displayValuesSupported", "setDisplayValuesSupported", defaultOpenIdProviderMetadata.getDisplayValuesSupported());
        }
        if (defaultOpenIdProviderMetadata.getClaimTypesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "claimTypesSupported", "setClaimTypesSupported", defaultOpenIdProviderMetadata.getClaimTypesSupported());
        }
        if (defaultOpenIdProviderMetadata.getTokenEndpointAuthMethodsSupported() != null) {
            addListStringSetterStatement(methodBuilder, "tokenEndpointAuthMethodsSupported", "setTokenEndpointAuthMethodsSupported", defaultOpenIdProviderMetadata.getTokenEndpointAuthMethodsSupported());
        }
        if (defaultOpenIdProviderMetadata.getResponseModesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "responseModesSupported", "setResponseModesSupported", defaultOpenIdProviderMetadata.getResponseModesSupported());
        }
        if (defaultOpenIdProviderMetadata.getAcrValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "acrValuesSupported", "setAcrValuesSupported", defaultOpenIdProviderMetadata.getAcrValuesSupported());
        }
        if (defaultOpenIdProviderMetadata.getGrantTypesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "grantTypesSupported", "setGrantTypesSupported", defaultOpenIdProviderMetadata.getGrantTypesSupported());
        }
        if (defaultOpenIdProviderMetadata.getRegistrationEndpoint() != null) {
            methodBuilder.addStatement("metadata.setRegistrationEndpoint($S)", defaultOpenIdProviderMetadata.getRegistrationEndpoint());
        }
        if (defaultOpenIdProviderMetadata.getServiceDocumentation() != null) {
            methodBuilder.addStatement("metadata.setServiceDocumentation($S)", defaultOpenIdProviderMetadata.getServiceDocumentation());
        }
        if (defaultOpenIdProviderMetadata.getClaimsLocalesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "claimsLocalesSupported", "setClaimsLocalesSupported", defaultOpenIdProviderMetadata.getClaimsLocalesSupported());
        }
        if (defaultOpenIdProviderMetadata.getUriLocalesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "uriLocalesSupported", "setUriLocalesSupported", defaultOpenIdProviderMetadata.getUriLocalesSupported());
        }
        if (defaultOpenIdProviderMetadata.getClaimsParameterSupported() != null) {
            methodBuilder.addStatement("metadata.setClaimsParameterSupported($S)", defaultOpenIdProviderMetadata.getClaimsParameterSupported());
        }
        if (defaultOpenIdProviderMetadata.getClaimsSupported() != null) {
            addListStringSetterStatement(methodBuilder, "claimsSupported", "setClaimsSupported", defaultOpenIdProviderMetadata.getClaimsSupported());
        }
        if (defaultOpenIdProviderMetadata.getCodeChallengeMethodsSupported() != null) {
            addListStringSetterStatement(methodBuilder, "codeChallengeMethodsSupported", "setCodeChallengeMethodsSupported", defaultOpenIdProviderMetadata.getCodeChallengeMethodsSupported());
        }
        if (defaultOpenIdProviderMetadata.getIntrospectionEndpoint() != null) {
            methodBuilder.addStatement("metadata.setIntrospectionEndpoint($S)", defaultOpenIdProviderMetadata.getIntrospectionEndpoint());
        }
        if (defaultOpenIdProviderMetadata.getIntrospectionEndpointAuthMethodsSupported() != null) {
            addListStringSetterStatement(methodBuilder, "introspectionEndpointAuthMethodsSupported", "setIntrospectionEndpointAuthMethodsSupported", defaultOpenIdProviderMetadata.getIntrospectionEndpointAuthMethodsSupported());
        }
        if (defaultOpenIdProviderMetadata.getRevocationEndpoint() != null) {
            methodBuilder.addStatement("metadata.setRevocationEndpoint($S)", defaultOpenIdProviderMetadata.getRevocationEndpoint());
        }
        if (defaultOpenIdProviderMetadata.getRevocationEndpointAuthMethodsSupported() != null) {
            addListStringSetterStatement(methodBuilder, "revocationEndpointAuthMethodsSupported", "setRevocationEndpointAuthMethodsSupported", defaultOpenIdProviderMetadata.getRevocationEndpointAuthMethodsSupported());
        }
        if (defaultOpenIdProviderMetadata.getCheckSessionIframe() != null) {
            methodBuilder.addStatement("metadata.setCheckSessionIframe($S)", defaultOpenIdProviderMetadata.getCheckSessionIframe());
        }
        if (defaultOpenIdProviderMetadata.getEndSessionEndpoint() != null) {
            methodBuilder.addStatement("metadata.setEndSessionEndpoint($S)", defaultOpenIdProviderMetadata.getEndSessionEndpoint());
        }
        if (defaultOpenIdProviderMetadata.getRequestUriParameterSupported() != null) {
            methodBuilder.addStatement("metadata.setRequestUriParameterSupported($S)", defaultOpenIdProviderMetadata.getRequestUriParameterSupported());
        }
        if (defaultOpenIdProviderMetadata.getOpPolicyUri() != null) {
            methodBuilder.addStatement("metadata.setOpPolicyUri($S)", defaultOpenIdProviderMetadata.getOpPolicyUri());
        }
        if (defaultOpenIdProviderMetadata.getOpTosUri() != null) {
            methodBuilder.addStatement("metadata.setOpTosUri($S)", defaultOpenIdProviderMetadata.getOpTosUri());
        }
        if (defaultOpenIdProviderMetadata.getRequestParameterSupported() != null) {
            methodBuilder.addStatement("metadata.setRequestParameterSupported($S)", defaultOpenIdProviderMetadata.getRequestParameterSupported());
        }
        if (defaultOpenIdProviderMetadata.getRequestObjectEncryptionAlgValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "requestObjectEncryptionAlgValuesSupported", "setRequestObjectEncryptionAlgValuesSupported", defaultOpenIdProviderMetadata.getRequestObjectEncryptionAlgValuesSupported());
        }
        if (defaultOpenIdProviderMetadata.getRequestObjectEncryptionEncValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "requestObjectEncryptionEncValuesSupported", "setRequestObjectEncryptionEncValuesSupported", defaultOpenIdProviderMetadata.getRequestObjectEncryptionEncValuesSupported());
        }
        if (defaultOpenIdProviderMetadata.getRequestObjectSigningAlgValuesSupported() != null) {
            addListStringSetterStatement(methodBuilder, "requestObjectSigningAlgValuesSupported", "setRequestObjectSigningAlgValuesSupported", defaultOpenIdProviderMetadata.getRequestObjectSigningAlgValuesSupported());
        }
        return methodBuilder.addStatement("return metadata").build();
    }

    private void addListStringSetterStatement(@NonNull MethodSpec.Builder methodBuilder,
                                              @NonNull String listVariableName,
                                              @NonNull String setter,
                                              @NonNull List<String> values) {
        methodBuilder.addStatement("$T<$T> " + listVariableName + " = new $T<>()", List.class, String.class, ArrayList.class);
        for (String value : values) {
            methodBuilder.addStatement(listVariableName + ".add($S)", value);
        }
        methodBuilder.addStatement("metadata."+setter+"(" + listVariableName + ")");
    }
}
