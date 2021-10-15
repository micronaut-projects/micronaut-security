package io.micronaut.security.token;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;

public interface ClaimsValidator {
    /**
     * @param claims  Claims
     * @param request HTTP request
     * @return whether claims pass validation.
     */
    boolean validate(@NonNull Claims claims, @Nullable HttpRequest<?> request);
}
