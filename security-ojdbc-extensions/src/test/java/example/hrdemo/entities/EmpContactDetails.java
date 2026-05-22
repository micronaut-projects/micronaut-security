package example.hrdemo.entities;

import io.micronaut.data.annotation.EmbeddedId;
import io.micronaut.data.annotation.MappedEntity;

@MappedEntity("emp_contact_details")
public class EmpContactDetails {

    @EmbeddedId
    private EmpContactDetailsId id;

    private String email;
    private String phone;
    private String location;

    public EmpContactDetails() {
    }

    public EmpContactDetails(EmpContactDetailsId id, String email, String phone, String location) {
        this.id = id;
        this.email = email;
        this.phone = phone;
        this.location = location;
    }

    public EmpContactDetailsId getId() {
        return id;
    }

    public void setId(EmpContactDetailsId id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }
}
