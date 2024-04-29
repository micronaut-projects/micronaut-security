package io.micronaut.security.token.jwt.validator.signature;

@FunctionalInterface
public interface JsonWebTokenSignatureValidator<T> {

    /**
     *
     * @param signedToken signed token
     * @return true if the token signature can be verfied.
     */
    boolean validateSignature(T signedToken);
}
