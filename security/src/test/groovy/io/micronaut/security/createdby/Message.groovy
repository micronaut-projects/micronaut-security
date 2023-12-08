package io.micronaut.security.createdby

import io.micronaut.core.annotation.Nullable
import io.micronaut.data.annotation.GeneratedValue
import io.micronaut.data.annotation.Id
import io.micronaut.data.annotation.MappedEntity
import jakarta.validation.constraints.NotBlank

@MappedEntity
class Message {
    @Id
    @GeneratedValue
    @Nullable
    Long id

    @NotBlank
    String title

    @Nullable
    String createdBy
}
