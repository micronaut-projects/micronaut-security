/*
 * Copyright 2017-2018 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.openid.configuration;

import javax.annotation.Nullable;
import java.util.List;

/**
 * Configuration for an OpenID Provider.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public interface OpenIdProviderConfiguration {

    /**
     * issuer.
     * @return URL using the https scheme with no query or fragment component that the Open ID Provider asserts as its Issuer Identifier.
     */
    @Nullable
    String getIssuer();

    /**
     * scopes_supported.
     * @return List of the OAuth 2.0 [RFC6749] scope values that this server supports.
     */
    @Nullable
    List<String> getScopesSupported();

    /**
     * response_types_supported.
     * @return List of the OAuth 2.0 response_type values that this Open ID Provider supports.
     */
    @Nullable
    List<String> getResponseTypesSupported();

    /**
     * subject_types_supported.
     * @return List of the Subject Identifier types that this OP supports.
     */
    @Nullable
    List<String> getSubjectTypesSupported();

    /**
     * id_token_encryption_enc_values_supported.
     * @return List of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
     */
    @Nullable
    List<String> getIdTokenEncryptionEncValuesSupported();


    /**
     * request_object_signing_alg_values_supported.
     * OPTIONAL
     * @return List of the JWS signing algorithms (alg values) supported by the OP for Request Objects.
     */
    @Nullable
    List<String> getRequestObjectSigningAlgValuesSupported();

    /**
     * @return URL of the Open ID Provider's JSON Web Key Set
     */
    @Nullable
    String getJwksUri();
}
