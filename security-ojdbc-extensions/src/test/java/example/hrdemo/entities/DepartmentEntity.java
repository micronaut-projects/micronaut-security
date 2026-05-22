package example.hrdemo.entities;

import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;

@MappedEntity("departments")
public record DepartmentEntity(
    @Id Long departmentId,
    String name,
    String description
) {
}
