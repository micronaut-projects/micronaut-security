package io.micronaut.security.docs.bearerauth;

import io.micronaut.serde.annotation.Serdeable;

@Serdeable
public record Book(String isbn, String name) {
}
