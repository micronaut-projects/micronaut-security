package example.hrdemo.entities;

import io.micronaut.data.annotation.Embeddable;
import io.micronaut.data.annotation.MappedProperty;

import java.util.Objects;

@Embeddable
public class ManagerId {

    @MappedProperty("manager_id")
    private Long managerId;

    @MappedProperty("employee_id")
    private Long employeeId;

    public ManagerId() {
    }

    public ManagerId(Long managerId, Long employeeId) {
        this.managerId = managerId;
        this.employeeId = employeeId;
    }

    public Long getManagerId() {
        return managerId;
    }

    public void setManagerId(Long managerId) {
        this.managerId = managerId;
    }

    public Long getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(Long employeeId) {
        this.employeeId = employeeId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ManagerId managerId1 = (ManagerId) o;
        return Objects.equals(managerId, managerId1.managerId)
            && Objects.equals(employeeId, managerId1.employeeId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(managerId, employeeId);
    }
}
