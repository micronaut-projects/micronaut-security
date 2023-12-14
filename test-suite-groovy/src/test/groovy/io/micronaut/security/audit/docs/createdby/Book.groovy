package io.micronaut.security.audit.docs.createdby
//tag::clazz[]
import io.micronaut.core.annotation.Nullable
import io.micronaut.data.annotation.GeneratedValue
import io.micronaut.data.annotation.Id
import io.micronaut.data.annotation.MappedEntity
import io.micronaut.security.annotation.CreatedBy
import io.micronaut.security.annotation.UpdatedBy
import jakarta.validation.constraints.NotBlank

@MappedEntity //1
class Book {

    @Id
    @GeneratedValue
    @Nullable
    private Long id

    @NotBlank
    private String title

    @NotBlank
    private String author

    @CreatedBy //2
    private String creator

    @UpdatedBy //3
    private String editor

    Long getId() {
        return id
    }

    void setId(Long id) {
        this.id = id
    }

    String getTitle() {
        return title
    }

    void setTitle(String title) {
        this.title = title
    }

    String getAuthor() {
        return author
    }

    void setAuthor(String author) {
        this.author = author
    }

    String getCreator() {
        return creator
    }

    void setCreator(String creator) {
        this.creator = creator
    }

    String getEditor() {
        return editor
    }

    void setEditor(String editor) {
        this.editor = editor
    }
}
//end::clazz[]
