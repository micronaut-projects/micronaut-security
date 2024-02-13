package io.micronaut.security.tests.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class ResourceEntity {

    @Id
    private Long ui;

    private String resourceId;

    private String description;


    public Long getUi() {
        return ui;
    }

    public void setUi(Long ui) {
        this.ui = ui;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
