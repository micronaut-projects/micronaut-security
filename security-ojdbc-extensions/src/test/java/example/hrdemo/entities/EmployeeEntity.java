package example.hrdemo.entities;

import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.MappedProperty;

import java.math.BigDecimal;

@MappedEntity("employees")
public class EmployeeEntity {

    @Id
    @MappedProperty("employee_id")
    private Long employeeId;

    @MappedProperty("first_name")
    private String firstName;

    @MappedProperty("last_name")
    private String lastName;

    @MappedProperty("job_code")
    private String jobCode;

    @MappedProperty("department_id")
    private Long departmentId;

    private String ssn;
    private byte[] photo;
    private BigDecimal salary;

    @MappedProperty("user_name")
    private String userName;

    @MappedProperty("manager_id")
    private Long managerId;

    public EmployeeEntity() {
    }

    public EmployeeEntity(Long employeeId,
                          String firstName,
                          String lastName,
                          String jobCode,
                          Long departmentId,
                          String ssn,
                          byte[] photo,
                          BigDecimal salary,
                          String userName,
                          Long managerId) {
        this.employeeId = employeeId;
        this.firstName = firstName;
        this.lastName = lastName;
        this.jobCode = jobCode;
        this.departmentId = departmentId;
        this.ssn = ssn;
        this.photo = photo;
        this.salary = salary;
        this.userName = userName;
        this.managerId = managerId;
    }

    public Long getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(Long employeeId) {
        this.employeeId = employeeId;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getJobCode() {
        return jobCode;
    }

    public void setJobCode(String jobCode) {
        this.jobCode = jobCode;
    }

    public Long getDepartmentId() {
        return departmentId;
    }

    public void setDepartmentId(Long departmentId) {
        this.departmentId = departmentId;
    }

    public String getSsn() {
        return ssn;
    }

    public void setSsn(String ssn) {
        this.ssn = ssn;
    }

    public byte[] getPhoto() {
        return photo;
    }

    public void setPhoto(byte[] photo) {
        this.photo = photo;
    }

    public BigDecimal getSalary() {
        return salary;
    }

    public void setSalary(BigDecimal salary) {
        this.salary = salary;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public Long getManagerId() {
        return managerId;
    }

    public void setManagerId(Long managerId) {
        this.managerId = managerId;
    }
}
