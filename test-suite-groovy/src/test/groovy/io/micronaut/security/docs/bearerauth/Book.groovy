package io.micronaut.security.docs.bearerauth

import io.micronaut.serde.annotation.Serdeable

@Serdeable
class Book {
    final String isbn
    final String name

    Book(String isbn, String name) {
        this.isbn = isbn
        this.name = name
    }
}
