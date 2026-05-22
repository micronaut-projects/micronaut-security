package example.hrdemo.entities;

import io.micronaut.data.annotation.EmbeddedId;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.MappedProperty;

@MappedEntity("emp_timecards")
public class EmpTimecard {

    @EmbeddedId
    private EmpTimecardId id;

    @MappedProperty("monday_hours")
    private Integer mondayHours;

    @MappedProperty("monday_type")
    private String mondayType;

    @MappedProperty("tuesday_hours")
    private Integer tuesdayHours;

    @MappedProperty("tuesday_type")
    private String tuesdayType;

    @MappedProperty("wednesday_hours")
    private Integer wednesdayHours;

    @MappedProperty("wednesday_type")
    private String wednesdayType;

    @MappedProperty("thursday_hours")
    private Integer thursdayHours;

    @MappedProperty("thursday_type")
    private String thursdayType;

    @MappedProperty("friday_hours")
    private Integer fridayHours;

    @MappedProperty("friday_type")
    private String fridayType;

    @MappedProperty("saturday_hours")
    private Integer saturdayHours;

    @MappedProperty("saturday_type")
    private String saturdayType;

    @MappedProperty("sunday_hours")
    private Integer sundayHours;

    @MappedProperty("sunday_type")
    private String sundayType;

    private String status;

    public EmpTimecard() {
    }

    public EmpTimecard(EmpTimecardId id,
                       Integer mondayHours,
                       String mondayType,
                       Integer tuesdayHours,
                       String tuesdayType,
                       Integer wednesdayHours,
                       String wednesdayType,
                       Integer thursdayHours,
                       String thursdayType,
                       Integer fridayHours,
                       String fridayType,
                       Integer saturdayHours,
                       String saturdayType,
                       Integer sundayHours,
                       String sundayType,
                       String status) {
        this.id = id;
        this.mondayHours = mondayHours;
        this.mondayType = mondayType;
        this.tuesdayHours = tuesdayHours;
        this.tuesdayType = tuesdayType;
        this.wednesdayHours = wednesdayHours;
        this.wednesdayType = wednesdayType;
        this.thursdayHours = thursdayHours;
        this.thursdayType = thursdayType;
        this.fridayHours = fridayHours;
        this.fridayType = fridayType;
        this.saturdayHours = saturdayHours;
        this.saturdayType = saturdayType;
        this.sundayHours = sundayHours;
        this.sundayType = sundayType;
        this.status = status;
    }

    public EmpTimecardId getId() {
        return id;
    }

    public void setId(EmpTimecardId id) {
        this.id = id;
    }

    public Integer getMondayHours() {
        return mondayHours;
    }

    public void setMondayHours(Integer mondayHours) {
        this.mondayHours = mondayHours;
    }

    public String getMondayType() {
        return mondayType;
    }

    public void setMondayType(String mondayType) {
        this.mondayType = mondayType;
    }

    public Integer getTuesdayHours() {
        return tuesdayHours;
    }

    public void setTuesdayHours(Integer tuesdayHours) {
        this.tuesdayHours = tuesdayHours;
    }

    public String getTuesdayType() {
        return tuesdayType;
    }

    public void setTuesdayType(String tuesdayType) {
        this.tuesdayType = tuesdayType;
    }

    public Integer getWednesdayHours() {
        return wednesdayHours;
    }

    public void setWednesdayHours(Integer wednesdayHours) {
        this.wednesdayHours = wednesdayHours;
    }

    public String getWednesdayType() {
        return wednesdayType;
    }

    public void setWednesdayType(String wednesdayType) {
        this.wednesdayType = wednesdayType;
    }

    public Integer getThursdayHours() {
        return thursdayHours;
    }

    public void setThursdayHours(Integer thursdayHours) {
        this.thursdayHours = thursdayHours;
    }

    public String getThursdayType() {
        return thursdayType;
    }

    public void setThursdayType(String thursdayType) {
        this.thursdayType = thursdayType;
    }

    public Integer getFridayHours() {
        return fridayHours;
    }

    public void setFridayHours(Integer fridayHours) {
        this.fridayHours = fridayHours;
    }

    public String getFridayType() {
        return fridayType;
    }

    public void setFridayType(String fridayType) {
        this.fridayType = fridayType;
    }

    public Integer getSaturdayHours() {
        return saturdayHours;
    }

    public void setSaturdayHours(Integer saturdayHours) {
        this.saturdayHours = saturdayHours;
    }

    public String getSaturdayType() {
        return saturdayType;
    }

    public void setSaturdayType(String saturdayType) {
        this.saturdayType = saturdayType;
    }

    public Integer getSundayHours() {
        return sundayHours;
    }

    public void setSundayHours(Integer sundayHours) {
        this.sundayHours = sundayHours;
    }

    public String getSundayType() {
        return sundayType;
    }

    public void setSundayType(String sundayType) {
        this.sundayType = sundayType;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
