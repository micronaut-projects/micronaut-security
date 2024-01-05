package io.micronaut.security.audit.docs.createdby;
//tag::clazz[]
import io.micronaut.core.annotation.Nullable;
import io.micronaut.data.annotation.GeneratedValue;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.security.annotation.CreatedBy;
import io.micronaut.security.annotation.UpdatedBy;
import jakarta.validation.constraints.NotBlank;

@MappedEntity //1
public record Book(
    @Id
    @GeneratedValue
    @Nullable
    Long id,

    @NotBlank
    String title,

    @NotBlank
    String author,

    @Nullable
    @CreatedBy //2
    String creator,

    @Nullable
    @UpdatedBy //3
    String editor) {
}
//end::clazz[]
