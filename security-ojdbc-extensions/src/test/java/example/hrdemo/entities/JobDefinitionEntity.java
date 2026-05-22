package example.hrdemo.entities;

import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.MappedProperty;

@MappedEntity("job_definitions")
public class JobDefinitionEntity {

    @Id
    @MappedProperty("job_code")
    private String jobCode;

    private String name;
    private String description;
    private String type;

    public JobDefinitionEntity() {
    }

    public JobDefinitionEntity(String jobCode, String name, String description, String type) {
        this.jobCode = jobCode;
        this.name = name;
        this.description = description;
        this.type = type;
    }

    public String getJobCode() {
        return jobCode;
    }

    public void setJobCode(String jobCode) {
        this.jobCode = jobCode;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
