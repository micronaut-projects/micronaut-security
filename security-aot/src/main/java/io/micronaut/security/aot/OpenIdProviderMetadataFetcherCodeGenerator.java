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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.optim.StaticOptimizations;
import io.micronaut.core.util.StringUtils;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadata;
import io.micronaut.security.oauth2.client.DefaultOpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadataFetcher;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;

import javax.lang.model.element.Modifier;
import java.util.Collection;
import java.util.HashMap;
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
    @SuppressWarnings("WeakerAccess")
    public static final String SECURITY_AOT_MODULE_ID = "micronaut.security.xxx";

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
                if (clientConfig.getIssuer().isPresent() && ctx.containsBean(OpenIdProviderMetadataFetcher.class, Qualifiers.byName(clientConfig.getName()))) {
                    OpenIdProviderMetadataFetcher fetcher = ctx.getBean(OpenIdProviderMetadataFetcher.class, Qualifiers.byName(clientConfig.getName()));
                    DefaultOpenIdProviderMetadata defaultOpenIdProviderMetadata = fetcher.fetch();
                    String simpleName = "Aot" + OpenIdProviderMetadataFetcher.class.getSimpleName() + StringUtils.capitalize(clientConfig.getName());
                    context.registerGeneratedSourceFile(generateJavaFile(context, simpleName, defaultOpenIdProviderMetadata));
                    body.addStatement("context.put($S, $T::create)", clientConfig.getName(), ClassName.bestGuess(simpleName));
                }
            }
            body.addStatement("$T.set($T, configs)", StaticOptimizations.class, DefaultOpenIdProviderMetadataFetcher.Optimizations.class);
        }));
    }

    private JavaFile generateJavaFile(@NonNull AOTContext context,
                                      @NonNull String fileSimpleName,
                                      @NonNull DefaultOpenIdProviderMetadata defaultOpenIdProviderMetadata) {
        TypeSpec.Builder builder = TypeSpec.classBuilder(fileSimpleName)
                .addModifiers(Modifier.PUBLIC)
                .addMethod(MethodSpec.methodBuilder("create")
                        .returns(DefaultOpenIdProviderMetadata.class)
                        .addModifiers(Modifier.PUBLIC, Modifier.STATIC)
                        .addStatement("$T metadata = new $T()", DefaultOpenIdProviderMetadata.class, DefaultOpenIdProviderMetadata.class)
                        .addStatement("metadata.setUserinfoEndpoint($S)", defaultOpenIdProviderMetadata.getUserinfoEndpoint())
                        .addStatement("return metadata")
                        .build());
                        /*
        public void setRequireRequestUriRegistration(@Nullable Boolean requireRequestUriRegistration);
public void setAuthorizationEndpoint(@NonNull String authorizationEndpoint);
public void setUserinfoEncryptionEncValuesSupported(@Nullable List<String> userinfoEncryptionEncValuesSupported);
public void setIdTokenEncryptionEncValuesSupported(@Nullable List<String> idTokenEncryptionEncValuesSupported);
public void setUserinfoEncryptionAlgValuesSupported(@Nullable List<String> userinfoEncryptionAlgValuesSupported);
public void setIdTokenSigningAlgValuesSupported(@NonNull List<String> idTokenSigningAlgValuesSupported);
public void setIssuer(@NonNull String issuer);
public void setJwksUri(@NonNull String jwksUri);
public void setResponseTypesSupported(@Nullable List<String> responseTypesSupported);
public void setScopesSupported(@Nullable List<String> scopesSupported);
public void setSubjectTypesSupported(@NonNull List<String> subjectTypesSupported);
public void setTokenEndpoint(@Nullable String tokenEndpoint);
public void setTokenEndpointAuthSigningAlgValuesSupported(@Nullable List<String> tokenEndpointAuthSigningAlgValuesSupported);
public void setDisplayValuesSupported(@Nullable List<String> displayValuesSupported);
public void setClaimTypesSupported(@Nullable List<String> claimTypesSupported);
public void setTokenEndpointAuthMethodsSupported(@Nullable List<String> tokenEndpointAuthMethodsSupported);

public void setResponseModesSupported(@Nullable List<String> responseModesSupported);
public void setAcrValuesSupported(@Nullable List<String> acrValuesSupported);
public void setGrantTypesSupported(@Nullable List<String> grantTypesSupported);
public void setRegistrationEndpoint(@Nullable String registrationEndpoint);
public void setServiceDocumentation(@Nullable String serviceDocumentation);
public void setClaimsLocalesSupported(@Nullable List<String> claimsLocalesSupported);
public void setUriLocalesSupported(@Nullable List<String> uriLocalesSupported);
public void setClaimsParameterSupported(@Nullable Boolean claimsParameterSupported);
public void setClaimsSupported(@Nullable List<String> claimsSupported);
public void setCodeChallengeMethodsSupported(@Nullable List<String> codeChallengeMethodsSupported);
public void setIntrospectionEndpoint(@Nullable String introspectionEndpoint);
public void setIntrospectionEndpointAuthMethodsSupported(@Nullable List<String> introspectionEndpointAuthMethodsSupported);
public void setRevocationEndpoint(@Nullable String revocationEndpoint);
public void setRevocationEndpointAuthMethodsSupported(@Nullable List<String> revocationEndpointAuthMethodsSupported);
public void setCheckSessionIframe(@Nullable String checkSessionIframe);
public void setEndSessionEndpoint(@Nullable String endSessionEndpoint);
public void setRequestUriParameterSupported(@Nullable Boolean requestUriParameterSupported);
public void setOpPolicyUri(@Nullable String opPolicyUri);
public void setOpTosUri(@Nullable String opTosUri);
public void setRequestParameterSupported(@Nullable Boolean requestParameterSupported);
public void setRequestObjectEncryptionAlgValuesSupported(@Nullable List<String> requestObjectEncryptionAlgValuesSupported);
public void setRequestObjectEncryptionEncValuesSupported(@Nullable List<String> requestObjectEncryptionEncValuesSupported);
public void setRequestObjectSigningAlgValuesSupported(@Nullable List<String> requestObjectSigningAlgValuesSupported);
                        */
        return context.javaFile(builder.build());
    }


}
