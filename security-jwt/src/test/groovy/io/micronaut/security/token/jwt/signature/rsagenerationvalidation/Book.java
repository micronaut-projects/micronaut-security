package io.micronaut.security.token.jwt.signature.rsagenerationvalidation;

import io.micronaut.serde.annotation.Serdeable;

@Serdeable
public class Book {
    private String title;

    public Book() {

    }

    public Book(String title) {
        this.title = title;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }
}
