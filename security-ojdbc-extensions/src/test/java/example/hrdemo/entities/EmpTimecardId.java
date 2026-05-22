package example.hrdemo.entities;

import io.micronaut.data.annotation.Embeddable;
import io.micronaut.data.annotation.MappedProperty;

import java.time.LocalDate;
import java.util.Objects;

@Embeddable
public class EmpTimecardId {

    @MappedProperty("week_start_date")
    private LocalDate weekStartDate;

    @MappedProperty("employee_id")
    private Long employeeId;

    public EmpTimecardId() {
    }

    public EmpTimecardId(LocalDate weekStartDate, Long employeeId) {
        this.weekStartDate = weekStartDate;
        this.employeeId = employeeId;
    }

    public LocalDate getWeekStartDate() {
        return weekStartDate;
    }

    public void setWeekStartDate(LocalDate weekStartDate) {
        this.weekStartDate = weekStartDate;
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
        EmpTimecardId that = (EmpTimecardId) o;
        return Objects.equals(weekStartDate, that.weekStartDate)
            && Objects.equals(employeeId, that.employeeId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(weekStartDate, employeeId);
    }
}
