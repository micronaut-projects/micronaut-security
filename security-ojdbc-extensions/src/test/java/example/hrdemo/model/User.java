package example.hrdemo.model;

import io.micronaut.core.annotation.Introspected;

@Introspected
public record User(Long id, String name) {
}
