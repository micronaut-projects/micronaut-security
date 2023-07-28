package io.micronaut.security.oauth2.client

import io.micronaut.core.annotation.ReflectiveAccess
import io.micronaut.core.beans.BeanIntrospection
import io.micronaut.core.type.Argument
import io.micronaut.json.JsonMapper
import io.micronaut.json.tree.JsonNode
import io.micronaut.security.testutils.ApplicationContextSpecification
import io.micronaut.serde.SerdeIntrospections

class DefaultOpenIdProviderMetadataSpec extends ApplicationContextSpecification {
    void "DefaultOpenIdProviderMetadata is annotated with ReflectiveAccess"() {
        expect:
        DefaultOpenIdProviderMetadata.class.isAnnotationPresent(ReflectiveAccess)
    }

    void "DefaultOpenIdProviderMetadata is annotated with @Introspected"() {
        when:
        BeanIntrospection.getIntrospection(DefaultOpenIdProviderMetadata)

        then:
        noExceptionThrown()
    }

    void "DefaultOpenIdProviderMetadata is annotated with @Serdeable.Deserializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getDeserializableIntrospection(Argument.of(DefaultOpenIdProviderMetadata))

        then:
        noExceptionThrown()
    }

    void "DefaultOpenIdProviderMetadata is annotated with @Serdeable.Serializable"() {
        given:
        SerdeIntrospections serdeIntrospections = applicationContext.getBean(SerdeIntrospections)

        when:
        serdeIntrospections.getSerializableIntrospection(Argument.of(DefaultOpenIdProviderMetadata))

        then:
        noExceptionThrown()
    }

    void "DefaultOpenIdProviderMetadata offers a builder"() {
        given:
        String authorizationEndpoint = "authorizationEndpoint"
        List<String> idTokenSigningAlgValuesSupported = ["idTokenSigningAlgValuesSupported"]
        String issuer = "issuer"
        String jwksUri = "jwksUri"
        List<String> acrValuesSupported = ["acrValuesSupported"]
        List<String> responseTypesSupported = ["responseTypesSupported"]
        List<String> responseModesSupported = ["responseModesSupported"]
        List<String> scopesSupported = ["scopesSupported"]
        List<String> grantTypesSupported = ["grantTypesSupported"]
        List<String> subjectTypesSupported = ["subjectTypesSupported"]
        String tokenEndpoint = "tokenEndpoint"
        List<String> tokenEndpointAuthMethodsSupported = ["client_secret_post"]
        String userinfoEndpoint = "userinfoEndpoint"
        String registrationEndpoint = "registrationEndpoint"
        List<String> claimsSupported = ["claimsSupported"]
        List<String> codeChallengeMethodsSupported = ["codeChallengeMethodsSupported"]
        String introspectionEndpoint = "introspectionEndpoint"
        List<String> introspectionEndpointAuthMethodsSupported = ["introspectionEndpointAuthMethodsSupported"]
        String revocationEndpoint = "revocationEndpoint"
        List<String> revocationEndpointAuthMethodsSupported = ["revocationEndpointAuthMethodsSupported"]
        String endSessionEndpoint = "endSessionEndpoint"
        Boolean requestParameterSupported = Boolean.TRUE
        Boolean requestUriParameterSupported = Boolean.TRUE
        Boolean requireRequestUriRegistration = Boolean.TRUE
        List<String> requestObjectSigningAlgValuesSupported = ["requestObjectSigningAlgValuesSupported"]
        String serviceDocumentation ="serviceDocumentation"
        List<String> idTokenEncryptionEncValuesSupported = ["idTokenEncryptionEncValuesSupported"]
        List<String> displayValuesSupported = ["displayValuesSupported"]
        List<String> claimTypesSupported = ["claimTypesSupported"]
        Boolean claimsParameterSupported = Boolean.TRUE
        String opTosUri = "opTosUri"
        String opPolicyUri = "opPolicyUri"
        List<String> uriLocalesSupported = ["uriLocalesSupported"]
        List<String> claimsLocalesSupported = ["claimsLocalesSupported"]
        List<String> userinfoEncryptionAlgValuesSupported = ["userinfoEncryptionAlgValuesSupported"]
        List<String> userinfoEncryptionEncValuesSupported = ["userinfoEncryptionEncValuesSupported"]
        List<String> tokenEndpointAuthSigningAlgValuesSupported = ["tokenEndpointAuthSigningAlgValuesSupported"]
        List<String> requestObjectEncryptionAlgValuesSupported = ["requestObjectEncryptionAlgValuesSupported"]
        List<String> requestObjectEncryptionEncValuesSupported = ["requestObjectEncryptionEncValuesSupported"]
        String checkSessionIframe = "checkSessionIframe"

        when:
        DefaultOpenIdProviderMetadata metadata = DefaultOpenIdProviderMetadata.builder()
                .authorizationEndpoint(authorizationEndpoint)
                .idTokenSigningAlgValuesSupported(idTokenSigningAlgValuesSupported)
                .issuer(issuer)
                .jwksUri(jwksUri)
                .acrValuesSupported(acrValuesSupported)
                .responseTypesSupported(responseTypesSupported)
                .responseModesSupported(responseModesSupported)
                .scopesSupported(scopesSupported)
                .grantTypesSupported(grantTypesSupported)
                .subjectTypesSupported(subjectTypesSupported)
                .tokenEndpoint(tokenEndpoint)
                .tokenEndpointAuthMethodsSupported(tokenEndpointAuthMethodsSupported)
                .userinfoEndpoint(userinfoEndpoint)
                .registrationEndpoint(registrationEndpoint)
                .claimsSupported(claimsSupported)
                .codeChallengeMethodsSupported(codeChallengeMethodsSupported)
                .introspectionEndpoint(introspectionEndpoint)
                .introspectionEndpointAuthMethodsSupported(introspectionEndpointAuthMethodsSupported)
                .revocationEndpoint(revocationEndpoint)
                .revocationEndpointAuthMethodsSupported(revocationEndpointAuthMethodsSupported)
                .endSessionEndpoint(endSessionEndpoint)
                .requestParameterSupported(requestParameterSupported)
                .requestUriParameterSupported(requestUriParameterSupported)
                .requireRequestUriRegistration(requireRequestUriRegistration)
                .requestObjectSigningAlgValuesSupported(requestObjectSigningAlgValuesSupported)
                .serviceDocumentation(serviceDocumentation)
                .idTokenEncryptionEncValuesSupported(idTokenEncryptionEncValuesSupported)
                .displayValuesSupported(displayValuesSupported)
                .claimTypesSupported(claimTypesSupported)
                .claimsParameterSupported(claimsParameterSupported)
                .opTosUri(opTosUri)
                .opPolicyUri(opPolicyUri)
                .uriLocalesSupported(uriLocalesSupported)
                .claimsLocalesSupported(claimsLocalesSupported)
                .userinfoEncryptionAlgValuesSupported(userinfoEncryptionAlgValuesSupported)
                .userinfoEncryptionEncValuesSupported(userinfoEncryptionEncValuesSupported)
                .tokenEndpointAuthSigningAlgValuesSupported(tokenEndpointAuthSigningAlgValuesSupported)
                .requestObjectEncryptionAlgValuesSupported(requestObjectEncryptionAlgValuesSupported)
                .requestObjectEncryptionEncValuesSupported(requestObjectEncryptionEncValuesSupported)
                .checkSessionIframe(checkSessionIframe)
                .build()

        then:
        metadata.authorizationEndpoint == authorizationEndpoint
        metadata.idTokenSigningAlgValuesSupported == idTokenSigningAlgValuesSupported
        metadata.issuer == issuer
        metadata.jwksUri == jwksUri
        metadata.acrValuesSupported == acrValuesSupported
        metadata.responseTypesSupported == responseTypesSupported
        metadata.responseModesSupported == responseModesSupported
        metadata.scopesSupported == scopesSupported
        metadata.grantTypesSupported == grantTypesSupported
        metadata.subjectTypesSupported == subjectTypesSupported
        metadata.tokenEndpoint == tokenEndpoint
        metadata.tokenEndpointAuthMethodsSupported == tokenEndpointAuthMethodsSupported
        metadata.userinfoEndpoint == userinfoEndpoint
        metadata.registrationEndpoint == registrationEndpoint
        metadata.claimsSupported == claimsSupported
        metadata.codeChallengeMethodsSupported == codeChallengeMethodsSupported
        metadata.introspectionEndpoint == introspectionEndpoint
        metadata.introspectionEndpointAuthMethodsSupported == introspectionEndpointAuthMethodsSupported
        metadata.revocationEndpoint == revocationEndpoint
        metadata.revocationEndpointAuthMethodsSupported == revocationEndpointAuthMethodsSupported
        metadata.endSessionEndpoint == endSessionEndpoint
        metadata.requestParameterSupported == requestParameterSupported
        metadata.requestUriParameterSupported == requestUriParameterSupported
        metadata.requireRequestUriRegistration == requireRequestUriRegistration
        metadata.requestObjectSigningAlgValuesSupported == requestObjectSigningAlgValuesSupported
        metadata.serviceDocumentation == serviceDocumentation
        metadata.idTokenEncryptionEncValuesSupported == idTokenEncryptionEncValuesSupported
        metadata.displayValuesSupported == displayValuesSupported
        metadata.claimTypesSupported == claimTypesSupported
        metadata.claimsParameterSupported == claimsParameterSupported
        metadata.opTosUri == opTosUri
        metadata.opPolicyUri == opPolicyUri
        metadata.uriLocalesSupported == uriLocalesSupported
        metadata.claimsLocalesSupported == claimsLocalesSupported
        metadata.userInfoEncryptionAlgValuesSupported == userinfoEncryptionAlgValuesSupported
        metadata.userinfoEncryptionEncValuesSupported == userinfoEncryptionEncValuesSupported
        metadata.tokenEndpointAuthSigningAlgValuesSupported == tokenEndpointAuthSigningAlgValuesSupported
        metadata.requestObjectEncryptionAlgValuesSupported == requestObjectEncryptionAlgValuesSupported
        metadata.requestObjectEncryptionEncValuesSupported == requestObjectEncryptionEncValuesSupported
        metadata.checkSessionIframe == checkSessionIframe
    }

    void snakeCaseStrategyIsUsed() {
        given:
        JsonMapper jsonMapper = JsonMapper.createDefault()
        DefaultOpenIdProviderMetadata obj = new DefaultOpenIdProviderMetadata()
        obj.authorizationEndpoint = 'authorizationEndpoint'
        obj.issuer = 'issuer'
        obj.idTokenSigningAlgValuesSupported = ['idTokenSigningAlgValuesSupported']
        obj.jwksUri = 'jwksUri'
        obj.acrValuesSupported = ['acrValuesSupported']
        obj.responseTypesSupported = ['responseTypesSupported']
        obj.responseModesSupported = ['responseModesSupported']
        obj.scopesSupported = ['scopesSupported']
        obj.grantTypesSupported = ['grantTypesSupported']
        obj.subjectTypesSupported = ['subjectTypesSupported']
        obj.tokenEndpoint = 'tokenEndpoint'
        obj.tokenEndpointAuthMethodsSupported = ['client_secret_post']
        obj.userinfoEndpoint = 'userinfoEndpoint'
        obj.registrationEndpoint = 'registrationEndpoint'
        obj.claimsSupported = ['claimsSupported']
        obj.codeChallengeMethodsSupported = ['codeChallengeMethodsSupported']
        obj.introspectionEndpoint = 'introspectionEndpoint'
        obj.introspectionEndpointAuthMethodsSupported = ['introspectionEndpointAuthMethodsSupported']
        obj.revocationEndpoint = 'revocationEndpoint'
        obj.revocationEndpointAuthMethodsSupported = ['revocationEndpointAuthMethodsSupported']
        obj.endSessionEndpoint = 'endSessionEndpoint'
        obj.requestParameterSupported = true
        obj.requestUriParameterSupported = true
        obj.requireRequestUriRegistration = true
        obj.requireRequestUriRegistration = true
        obj.requestObjectSigningAlgValuesSupported = ['requestObjectSigningAlgValuesSupported']
        obj.serviceDocumentation = 'serviceDocumentation'
        obj.idTokenEncryptionEncValuesSupported = ['idTokenEncryptionEncValuesSupported']
        obj.displayValuesSupported = ['displayValuesSupported']
        obj.claimTypesSupported = ['claimTypesSupported']
        obj.claimsParameterSupported = true
        obj.opTosUri = 'opTosUri'
        obj.opPolicyUri = 'opPolicyUri'
        obj.uriLocalesSupported = ['uriLocalesSupported']
        obj.claimsLocalesSupported = ['claimsLocalesSupported']
        obj.userinfoEncryptionEncValuesSupported = ['userinfoEncryptionEncValuesSupported']
        obj.tokenEndpointAuthSigningAlgValuesSupported = ['tokenEndpointAuthSigningAlgValuesSupported']
        obj.requestObjectEncryptionAlgValuesSupported = ['requestObjectEncryptionAlgValuesSupported']
        obj.requestObjectEncryptionEncValuesSupported = ['requestObjectEncryptionEncValuesSupported']
        obj.checkSessionIframe = 'checkSessionIframe'
        obj.userinfoEncryptionAlgValuesSupported = ['userinfoEncryptionAlgValuesSupported']

        when:
        JsonNode jsonNode = jsonMapper.writeValueToTree(obj)

        then:
        jsonNode.isObject()
        'authorizationEndpoint' == jsonNode.get("authorization_endpoint").getStringValue()
        ['idTokenSigningAlgValuesSupported'] == jsonNode.get("id_token_signing_alg_values_supported").getValue() as List<String>
        'issuer' == jsonNode.get("issuer").getStringValue()
        'jwksUri' == jsonNode.get("jwks_uri").getStringValue()
        ['acrValuesSupported'] == jsonNode.get("acr_values_supported").getValue() as List<String>
        ['responseTypesSupported'] == jsonNode.get("response_types_supported").getValue() as List<String>
        ['responseModesSupported'] == jsonNode.get("response_modes_supported").getValue() as List<String>
        ['scopesSupported'] == jsonNode.get("scopes_supported").getValue() as List<String>
        ['grantTypesSupported'] == jsonNode.get("grant_types_supported").getValue() as List<String>
        ['subjectTypesSupported'] == jsonNode.get("subject_types_supported").getValue() as List<String>
        'tokenEndpoint' == jsonNode.get("token_endpoint").getStringValue()
        ['client_secret_post'] == jsonNode.get("token_endpoint_auth_methods_supported").getValue() as List<String>
        'userinfoEndpoint' == jsonNode.get("userinfo_endpoint").getStringValue()
        'registrationEndpoint' == jsonNode.get("registration_endpoint").getStringValue()
        ['claimsSupported'] == jsonNode.get("claims_supported").getValue() as List<String>
        ['codeChallengeMethodsSupported'] == jsonNode.get("code_challenge_methods_supported").getValue() as List<String>
        'introspectionEndpoint' == jsonNode.get("introspection_endpoint").getStringValue()
        ['introspectionEndpointAuthMethodsSupported'] == jsonNode.get("introspection_endpoint_auth_methods_supported").getValue() as List<String>
        'revocationEndpoint' == jsonNode.get("revocation_endpoint").getStringValue()
        ['revocationEndpointAuthMethodsSupported'] == jsonNode.get("revocation_endpoint_auth_methods_supported").getValue() as List<String>
        'endSessionEndpoint' == jsonNode.get("end_session_endpoint").getStringValue()
        jsonNode.get("request_parameter_supported").getBooleanValue()
        jsonNode.get("request_uri_parameter_supported").getBooleanValue()
        jsonNode.get("require_request_uri_registration").getBooleanValue()
        jsonNode.get("require_request_uri_registration").getBooleanValue()
        ['requestObjectSigningAlgValuesSupported'] == jsonNode.get("request_object_signing_alg_values_supported").getValue() as List<String>
        'serviceDocumentation' == jsonNode.get("service_documentation").getStringValue()
        ['idTokenEncryptionEncValuesSupported'] == jsonNode.get("id_token_encryption_enc_values_supported").getValue() as List<String>
        ['displayValuesSupported'] == jsonNode.get("display_values_supported").getValue() as List<String>
        ['claimTypesSupported'] == jsonNode.get("claim_types_supported").getValue() as List<String>
        jsonNode.get("claims_parameter_supported").getBooleanValue()
        'opTosUri' == jsonNode.get("op_tos_uri").getStringValue()
        'opPolicyUri' == jsonNode.get("op_policy_uri").getStringValue()
        ['uriLocalesSupported'] == jsonNode.get("uri_locales_supported").getValue() as List<String>
        ['claimsLocalesSupported'] == jsonNode.get("claims_locales_supported").getValue() as List<String>
        ['userinfoEncryptionEncValuesSupported'] == jsonNode.get("userinfo_encryption_enc_values_supported").getValue() as List<String>
        ['tokenEndpointAuthSigningAlgValuesSupported'] == jsonNode.get("token_endpoint_auth_signing_alg_values_supported").getValue() as List<String>
        ['requestObjectEncryptionAlgValuesSupported'] == jsonNode.get("request_object_encryption_alg_values_supported").getValue() as List<String>
        ['requestObjectEncryptionEncValuesSupported'] == jsonNode.get("request_object_encryption_enc_values_supported").getValue() as List<String>
        'checkSessionIframe' == jsonNode.get("check_session_iframe").getStringValue()
        ['userinfoEncryptionAlgValuesSupported'] == jsonNode.get("userinfo_encryption_alg_values_supported").getValue() as List<String>
    }

}
