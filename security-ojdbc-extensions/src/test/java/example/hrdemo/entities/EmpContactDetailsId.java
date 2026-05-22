package example.hrdemo.entities;

import io.micronaut.data.annotation.Embeddable;
import io.micronaut.data.annotation.MappedProperty;

import java.util.Objects;

@Embeddable
public class EmpContactDetailsId {

    @MappedProperty("employee_id")
    private Long employeeId;

    @MappedProperty("type")
    private String type;

    public EmpContactDetailsId() {
    }

    public EmpContactDetailsId(Long employeeId, String type) {
        this.employeeId = employeeId;
        this.type = type;
    }

    public Long getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(Long employeeId) {
        this.employeeId = employeeId;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        EmpContactDetailsId that = (EmpContactDetailsId) o;
        return Objects.equals(employeeId, that.employeeId)
            && Objects.equals(type, that.type);
    }

    @Override
    public int hashCode() {
        return Objects.hash(employeeId, type);
    }
}
