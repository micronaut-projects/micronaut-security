package io.micronaut.security.audit.docs.createdby;
//tag::clazz[]
import io.micronaut.core.annotation.Nullable;
import io.micronaut.data.annotation.GeneratedValue;
import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.security.audit.annotation.CreatedBy;
import io.micronaut.security.audit.annotation.UpdatedBy;
import jakarta.validation.constraints.NotBlank;

@MappedEntity //1
public class Book {

    @Id
    @GeneratedValue
    @Nullable
    private Long id;

    @NotBlank
    private String title;

    @NotBlank
    private String author;

    @CreatedBy //2
    private String creator;

    @UpdatedBy //3
    private String editor;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getAuthor() {
        return author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getCreator() {
        return creator;
    }

    public void setCreator(String creator) {
        this.creator = creator;
    }

    public String getEditor() {
        return editor;
    }

    public void setEditor(String editor) {
        this.editor = editor;
    }
}
//end::clazz[]
