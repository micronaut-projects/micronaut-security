package io.micronaut.security.token.jwt.validator.signature;

import io.micronaut.core.async.annotation.SingleResult;
import org.reactivestreams.Publisher;

@FunctionalInterface
public interface ReactiveJsonWebTokenSignatureValidator<T> {

    /**
     *
     * @param signedToken signed token
     * @return A publisher with a single result with a true boolean if the token signature can be verified.
     */
    @SingleResult
    Publisher<Boolean> validateSignature(T signedToken);
}
