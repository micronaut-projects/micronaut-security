package io.micronaut.security.audit

import io.micronaut.core.annotation.Nullable
import io.micronaut.data.annotation.GeneratedValue
import io.micronaut.data.annotation.Id
import io.micronaut.data.annotation.MappedEntity
import io.micronaut.security.annotation.CreatedBy
import io.micronaut.security.annotation.UpdatedBy
import jakarta.validation.constraints.NotBlank

@MappedEntity
class Message {
    @Id
    @GeneratedValue
    @Nullable
    Long id

    @NotBlank
    String title

    @CreatedBy
    @Nullable
    String creator

    @UpdatedBy
    @Nullable
    String lastModifiedBy
}
