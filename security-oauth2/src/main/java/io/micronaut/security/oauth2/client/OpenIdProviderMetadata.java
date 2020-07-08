/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.oauth2.client;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import java.util.List;

/**
 * Metadata describing the configuration of OpenID Providers.
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">Open ID Provider Metadata Spec</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
public interface OpenIdProviderMetadata {

    /**
     * issuer.
     * REQUIRED.
     * @return URL using the https scheme with no query or fragment component that the Open ID Provider asserts as its Issuer Identifier.
     */
    @NonNull
    String getIssuer();

    /**
     * authorization_endpoint.
     * REQUIRED.
     * @return URL of the Open ID Provider's OAuth 2.0 Authorization Endpoint
     */
    @NonNull
    String getAuthorizationEndpoint();

    /**
     * token_endpoint.
     * This is REQUIRED unless only the Implicit Flow is used.
     * @return URL of the Open ID Provider's OAuth 2.0 Token Endpoint
     */
    @NonNull
    String getTokenEndpoint();

    /**
     * userinfo_endpoint.
     * RECOMMENDED.
     * This URL MUST use the https scheme and MAY contain port, path, and query parameter components.
     * @return URL of the Open ID Provider's UserInfo Endpoint
     */
    @Nullable
    String getUserinfoEndpoint();

    /**
     * jwks_uri.
     * REQUIRED
     * @return URL of the Open ID Provider's JSON Web Key Set
     */
    @NonNull
    String getJwksUri();

    /**
     * registration_endpoint.
     * RECOMMENDED
     * @return URL of the Open ID Provider's Dynamic Client Registration Endpoint
     */
    @Nullable
    String getRegistrationEndpoint();

    /**
     * scopes_supported.
     * RECOMMENDED.
     * @return List of the OAuth 2.0 [RFC6749] scope values that this server supports.
     */
    @Nullable
    List<String> getScopesSupported();

    /**
     * response_types_supported.
     * REQUIRED
     * @return List of the OAuth 2.0 response_type values that this Open ID Provider supports.
     */
    @Nullable
    List<String> getResponseTypesSupported();

    /**
     * response_modes_supported.
     * OPTIONAL
     * @return List of the OAuth 2.0 response_mode values that this Open ID Provider supports.
     */
    @Nullable
    List<String> getResponseModesSupported();

    /**
     * grant_types_supported.
     * OPTIONAL
     * @return List of the OAuth 2.0 Grant Type values that this Open ID Provider supports.
     */
    @Nullable
    List<String> getGrantTypesSupported();

    /**
     * acr_values_supported.
     * OPTIONAL.
     * @return List of the Authentication Context Class References that this OP supports.
     */
    @Nullable
    List<String> getAcrValuesSupported();

    /**
     * subject_types_supported.
     * REQUIRED
     * @return List of the Subject Identifier types that this OP supports.
     */
    @NonNull
    List<String> getSubjectTypesSupported();

    /**
     * id_token_signing_alg_values_supported
     * REQUIRED.
     * @return List of the JWS signing algorithms (alg values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
     */
    @NonNull
    List<String> getIdTokenSigningAlgValuesSupported();

    /**
     * id_token_encryption_enc_values_supported
     * OPTIONAL.
     * @return List of the JWE encryption algorithms (enc values) supported by the OP for the ID Token to encode the Claims in a JWT [JWT].
     */
    @Nullable
    List<String> getIdTokenEncryptionEncValuesSupported();

    /**
     * userinfo_encryption_alg_values_supported.
     * OPTIONAL.
     * @return List of the JWE [JWE] encryption algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
     */
    @Nullable
    List<String> getUserInfoEncryptionAlgValuesSupported();

    /**
     * userinfo_encryption_enc_values_supported
     * OPTIONAL.
     * @return List of the JWE encryption algorithms (enc values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
     */
    @Nullable
    List<String> getUserinfoEncryptionEncValuesSupported();

    /**
     * request_object_signing_alg_values_supported.
     * OPTIONAL
     * @return List of the JWS signing algorithms (alg values) supported by the OP for Request Objects.
     */
    @Nullable
    List<String> getRequestObjectSigningAlgValuesSupported();

    /**
     * request_object_encryption_alg_values_supported
     * OPTIONAL.
     * @return list of the JWE encryption algorithms (alg values) supported by the OP for Request Objects.
     */
    @Nullable
    List<String> getRequestObjectEncryptionAlgValuesSupported();

    /**
     * request_object_encryption_enc_values_supported
     * OPTIONAL.
     * @return List of the JWE encryption algorithms (enc values) supported by the OP for Request Objects.
     */
    @Nullable
    List<String> getRequestObjectEncryptionEncValuesSupported();

    /**
     * token_endpoint_auth_methods_supported
     * OPTIONAL.
     * @return List of Client Authentication methods supported by this Token Endpoint.
     */
    @Nullable
    List<String> getTokenEndpointAuthMethodsSupported();

    /**
     * token_endpoint_auth_signing_alg_values_supported
     * OPTIONAL.
     * @return List of the JWS signing algorithms (alg values) supported by the Token Endpoint.
     */
    @Nullable
    List<String> getTokenEndpointAuthSigningAlgValuesSupported();

    /**
     * display_values_supported
     * OPTIONAL.
     *
     * @return List of the display parameter values that the OpenID Provider supports.
     */
    @Nullable
    List<String> getDisplayValuesSupported();

    /**
     * claim_types_supported
     * OPTIONAL.
     * @return List of the Claim Types that the OpenID Provider supports.
     */
    @Nullable
    List<String> getClaimTypesSupported();

    /**
     * claims_supported
     * RECOMMENDED.
     * @return List of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.
     */
    @Nullable
    List<String> getClaimsSupported();

    /**
     * service_documentation
     * OPTIONAL.
     * @return URL of a page containing human-readable information that developers might want or need to know when using the OpenID Provider.
     */
    @Nullable
    String getServiceDocumentation();

    /**
     * claims_locales_supported
     * OPTIONAL.
     * @return Languages and scripts supported for values in Claims
     */
    @Nullable
    List<String> getClaimsLocalesSupported();

    /**
     * ui_locales_supported
     * OPTIONAL.
     * @return Languages and scripts supported for the user interface
     */
    @Nullable
    List<String> getUriLocalesSupported();

    /**
     * claims_parameter_supported
     * OPTIONAL.
     * @return Boolean value specifying whether the OP supports use of the claims parameter.
     */
    @Nullable
    Boolean getClaimsParameterSupported();

    /**
     * request_parameter_supported
     * OPTIONAL.
     * @return Boolean value specifying whether the OP supports use of the request parameter, with true indicating support.
     */
    @Nullable
    Boolean getRequestParameterSupported();

    /**
     * request_uri_parameter_supported
     * OPTIONAL.
     * @return Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support.
     */
    @Nullable
    Boolean getRequestUriParameterSupported();

    /**
     * require_request_uri_registration
     * OPTIONAL.
     * @return Boolean value specifying whether the OP requires any request_uri values used to be pre-registered using the request_uris registration parameter. Pre-registration is REQUIRED when the value is true. If omitted, the default value is false.
     */
    @Nullable
    Boolean getRequireRequestUriRegistration();

    /**
     * op_policy_uri
     * OPTIONAL.
     * @return URL that the OpenID Provider provides to the person registering the Client to read about the OP's requirements on how the Relying Party can use the data provided by the OP.
     */
    @Nullable
    String getOpPolicyUri();

    /**
     * op_tos_uri.
     * OPTIONAL.
     * @return URL that the OpenID Provider provides to the person registering the Client to read about OpenID Provider's terms of service.
     */
    @Nullable
    String getOpTosUri();

    // This methods are not described in the spec but commonly used

    /**
     * code_challenge_methods_supported.
     * @return List of the supported transformation methods by the authorisation code verifier for Proof Key for Code Exchange (PKCE).
     */
    @Nullable
    List<String> getCodeChallengeMethodsSupported();

    /**
     *
     * @return List of Client Authentication methods supported by Introspection Endpoint
     */
    @Nullable
    List<String> getIntrospectionEndpointAuthMethodsSupported();

    /**
     *
     * @return List of Client Authentication methods supported by Revocation Endpoint
     */
    @Nullable
    List<String> getRevocationEndpointAuthMethodsSupported();

    /**
     * @see <a href="https://tools.ietf.org/html/rfc7662">OAuth 2.0 Token Introspection</a>
     * @return The fully qualified URL of the server's introspection endpoint defined by OAuth Token Introspection [RFC7662]
     */
    @Nullable
    String getIntrospectionEndpoint();

    /**
     * @see <a href="https://tools.ietf.org/html/rfc7009">OAuth 2.0 Token Revocation</a>
     * @return The fully qualified URL of the server's revocation endpoint defined by Oauth Token Revocation.
     */
    @Nullable
    String getRevocationEndpoint();


    /**
     * check_session_iframe.
     * REQUIRED
     * @return URL of an OP iframe that supports cross-origin communications for session state information with the RP Client, using the HTML5 postMessage API.
     */
    @Nullable
    String getCheckSessionIframe();

    /**
     * end_session_endpoint.
     * REQUIRED
     * @return URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP.
     */
    @Nullable
    String getEndSessionEndpoint();
}
