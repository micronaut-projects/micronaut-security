package io.micronaut.security.token.jwt.validator;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.jwt.encryption.JsonWebTokenEncryption;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import io.micronaut.security.token.jwt.parser.JsonWebTokenParser;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.signature.SignedJwtJsonWebTokenSignatureValidator;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

@Singleton
public class DefaultJsonWebTokenValidator<R> implements JsonWebTokenValidator<JWT, R> {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultJsonWebTokenValidator.class);
    private final JsonWebTokenEncryption<EncryptedJWT, SignedJWT> jsonWebTokenEncryption;
    private final JsonWebTokenParser<JWT> jsonWebTokenParser;
    private final SignedJwtJsonWebTokenSignatureValidator signatureValidator;
    private final boolean noSignatures;
    private final List<JwtClaimsValidator<R>> claimsValidators;

    public DefaultJsonWebTokenValidator(JsonWebTokenEncryption<EncryptedJWT, SignedJWT> jsonWebTokenEncryption,
                                        JsonWebTokenParser<JWT> jsonWebTokenParser,
                                        SignedJwtJsonWebTokenSignatureValidator signatureValidator,
                                        List<SignatureConfiguration> signatures,
                                        List<JwtClaimsValidator<R>> claimsValidators) {
        this.jsonWebTokenEncryption = jsonWebTokenEncryption;
        this.jsonWebTokenParser = jsonWebTokenParser;
        this.signatureValidator = signatureValidator;
        this.noSignatures = signatures.isEmpty();
        this.claimsValidators = claimsValidators;
    }

    @NonNull
    @Override
    public Optional<JWT> validate(@NonNull String token, @Nullable R request) {
        Optional<JWT> jwtOptional = jsonWebTokenParser.parse(token);
        if (jwtOptional.isEmpty()) {
            return Optional.empty();
        }
        JWT jwt = jwtOptional.get();
        if (!validateSignature(jwt)) {
            return Optional.empty();
        }
        if (claimsValidators.isEmpty()) {
            return Optional.of(jwt);
        }
        try {
            Claims claims = new JwtClaimsSetAdapter(jwt.getJWTClaimsSet());
            if (claimsValidators.stream().allMatch(validator -> validator.validate(claims, request))) {
                return Optional.of(jwt);
            }
        } catch (ParseException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to retrieve the claims set", e);
            }
        }
        return Optional.empty();
    }

    private boolean validateSignature(JWT jwt) {
        if (jwt instanceof PlainJWT plainJWT) {
            return validateSignature(plainJWT);

        } else if (jwt instanceof SignedJWT signedJWT) {
            return validateSignature(signedJWT);

        } else if (jwt instanceof EncryptedJWT encryptedJWT) {
            Optional<SignedJWT> optionalSignedJWT = jsonWebTokenEncryption.decrypt(encryptedJWT);
            if (optionalSignedJWT.isEmpty()) {
                return false;
            }
            SignedJWT signedJWT = optionalSignedJWT.get();
            return validateSignature(signedJWT);
        }
        return false;
    }

    private boolean validateSignature(SignedJWT signedJWT) {
        return signatureValidator.validateSignature(signedJWT);
    }

    private boolean validateSignature(PlainJWT plainJWT) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validating plain JWT");
        }
        if (noSignatures) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT is not signed and no signature configurations -> verified");
            }
            return true;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("A non-signed JWT cannot be accepted as signature configurations have been defined");
            }
            return false;
        }
    }
}
