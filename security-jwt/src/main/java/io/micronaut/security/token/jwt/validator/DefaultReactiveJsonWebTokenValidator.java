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
import io.micronaut.security.token.jwt.validator.signature.JsonWebTokenSignatureValidator;
import io.micronaut.security.token.jwt.validator.signature.ReactiveJsonWebTokenSignatureValidator;
import io.micronaut.security.token.jwt.validator.signature.SignedJwtJsonWebTokenSignatureValidator;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

@Singleton
public class DefaultReactiveJsonWebTokenValidator<R> implements ReactiveJsonWebTokenValidator<JWT, R> {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultReactiveJsonWebTokenValidator.class);
    private final JsonWebTokenEncryption<EncryptedJWT, SignedJWT> jsonWebTokenEncryption;
    private final JsonWebTokenParser<JWT> jsonWebTokenParser;
    private final ReactiveJsonWebTokenSignatureValidator<SignedJWT> signatureValidator;
    private final boolean noSignatures;
    private final List<JwtClaimsValidator<R>> claimsValidators;

    public DefaultReactiveJsonWebTokenValidator(JsonWebTokenEncryption<EncryptedJWT, SignedJWT> jsonWebTokenEncryption,
                                                JsonWebTokenParser<JWT> jsonWebTokenParser,
                                                ReactiveJsonWebTokenSignatureValidator signatureValidator,
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
    public Publisher<JWT> validate(@NonNull String token, @Nullable R request) {
        Optional<JWT> jwtOptional = jsonWebTokenParser.parse(token);
        if (jwtOptional.isEmpty()) {
            return Mono.empty();
        }
        JWT jwt = jwtOptional.get();
        return validateSignature(jwt)
                .filter(valid -> valid && validateClaims(jwt, request))
                .map(valid -> jwt);
    }

    @NonNull
    private boolean validateClaims(@NonNull JWT jwt, @Nullable R request) {
        if (claimsValidators.isEmpty()) {
            return true;
        }
        try {
            Claims claims = new JwtClaimsSetAdapter(jwt.getJWTClaimsSet());
            return claimsValidators.stream().allMatch(validator -> validator.validate(claims, request));
        } catch (ParseException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to retrieve the claims set", e);
            }
        }
        return false;
    }

    private Mono<Boolean> validateSignature(JWT jwt) {
        if (jwt instanceof PlainJWT plainJWT) {
            return Mono.just(validateSignature(plainJWT));

        } else if (jwt instanceof SignedJWT signedJWT) {
            return validateSignature(signedJWT);

        } else if (jwt instanceof EncryptedJWT encryptedJWT) {
            Optional<SignedJWT> optionalSignedJWT = jsonWebTokenEncryption.decrypt(encryptedJWT);
            if (optionalSignedJWT.isEmpty()) {
                return Mono.just(false);
            }
            SignedJWT signedJWT = optionalSignedJWT.get();
            return validateSignature(signedJWT);
        }
        return Mono.just(false);
    }

    private Mono<Boolean> validateSignature(SignedJWT signedJWT) {
        return Mono.from(signatureValidator.validateSignature(signedJWT));
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
