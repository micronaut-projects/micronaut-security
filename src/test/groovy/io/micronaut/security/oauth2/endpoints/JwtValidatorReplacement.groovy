package io.micronaut.security.oauth2.endpoints

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.DefaultAuthentication
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration
import io.micronaut.security.token.jwt.signature.SignatureConfiguration
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator
import io.micronaut.security.token.jwt.validator.JwtClaimsValidator
import io.micronaut.security.token.jwt.validator.JwtTokenValidator

import javax.inject.Singleton

@Replaces(JwtTokenValidator)
@Singleton
@Requires(property = 'spec.name', value='AuthorizationCodeControllerSpec')
class JwtValidatorReplacement extends JwtTokenValidator {
    JwtValidatorReplacement(Collection<SignatureConfiguration> signatureConfigurations, Collection<EncryptionConfiguration> encryptionConfigurations, Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators) {
        super(signatureConfigurations, encryptionConfigurations, genericJwtClaimsValidators)
    }

    Optional<Authentication> authenticationIfValidJwtSignatureAndClaims(String token, Collection<? extends JwtClaimsValidator> claimsValidators) {
        Optional.of(new DefaultAuthentication("user", [:]))
    }
}
