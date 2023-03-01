package io.micronaut.security.oauth2.client

import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.core.annotation.ReflectiveAccess
import spock.lang.Specification

class DefaultOpenIdProviderMetadataSpec extends Specification {
    void "DefaultOpenIdProviderMetadata is annotated with ReflectiveAccess"() {
        expect:
        DefaultOpenIdProviderMetadata.class.isAnnotationPresent(ReflectiveAccess)
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
        List<String> tokenEndpointAuthMethodsSupported = ["tokenEndpointAuthMethodsSupported"]
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
}
