package example.hrdemo.entities;

import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.MappedProperty;

@MappedEntity("emp_beneficiaries")
public class EmpBeneficiary {

    @Id
    @MappedProperty("beneficiary_id")
    private Long beneficiaryId;

    @MappedProperty("employee_id")
    private Long employeeId;

    @MappedProperty("first_name")
    private String firstName;

    @MappedProperty("last_name")
    private String lastName;

    private String relationship;

    public EmpBeneficiary() {
    }

    public EmpBeneficiary(Long beneficiaryId, Long employeeId, String firstName, String lastName, String relationship) {
        this.beneficiaryId = beneficiaryId;
        this.employeeId = employeeId;
        this.firstName = firstName;
        this.lastName = lastName;
        this.relationship = relationship;
    }

    public Long getBeneficiaryId() {
        return beneficiaryId;
    }

    public void setBeneficiaryId(Long beneficiaryId) {
        this.beneficiaryId = beneficiaryId;
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

    public String getRelationship() {
        return relationship;
    }

    public void setRelationship(String relationship) {
        this.relationship = relationship;
    }
}
