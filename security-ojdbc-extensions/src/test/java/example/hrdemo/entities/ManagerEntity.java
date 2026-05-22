package example.hrdemo.entities;

import io.micronaut.data.annotation.EmbeddedId;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.MappedProperty;

@MappedEntity("managers")
public class ManagerEntity {

    @EmbeddedId
    private ManagerId id;

    @MappedProperty("mgr_user_name")
    private String mgrUserName;

    @MappedProperty("mgr_first_name")
    private String mgrFirstName;

    @MappedProperty("mgr_last_name")
    private String mgrLastName;

    public ManagerEntity() {
    }

    public ManagerEntity(ManagerId id, String mgrUserName, String mgrFirstName, String mgrLastName) {
        this.id = id;
        this.mgrUserName = mgrUserName;
        this.mgrFirstName = mgrFirstName;
        this.mgrLastName = mgrLastName;
    }

    public ManagerId getId() {
        return id;
    }

    public void setId(ManagerId id) {
        this.id = id;
    }

    public String getMgrUserName() {
        return mgrUserName;
    }

    public void setMgrUserName(String mgrUserName) {
        this.mgrUserName = mgrUserName;
    }

    public String getMgrFirstName() {
        return mgrFirstName;
    }

    public void setMgrFirstName(String mgrFirstName) {
        this.mgrFirstName = mgrFirstName;
    }

    public String getMgrLastName() {
        return mgrLastName;
    }

    public void setMgrLastName(String mgrLastName) {
        this.mgrLastName = mgrLastName;
    }
}
