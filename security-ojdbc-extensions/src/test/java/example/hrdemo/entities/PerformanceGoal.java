package example.hrdemo.entities;

import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.MappedProperty;

@MappedEntity("performance_goals")
public class PerformanceGoal {

    @Id
    @MappedProperty("goal_id")
    private Long goalId;

    @MappedProperty("employee_id")
    private Long employeeId;

    @MappedProperty("goal_name")
    private String goalName;

    @MappedProperty("year")
    private Integer year;

    private String description;

    @MappedProperty("emp_comments")
    private String empComments;

    @MappedProperty("mgr_feedback")
    private String mgrFeedback;

    @MappedProperty("mgr_private_notes")
    private String mgrPrivateNotes;

    @MappedProperty("emp_overall_rating")
    private Integer empOverallRating;

    @MappedProperty("mgr_overall_rating")
    private Integer mgrOverallRating;

    private String status;

    public PerformanceGoal() {
    }

    public PerformanceGoal(Long goalId,
                           Long employeeId,
                           String goalName,
                           Integer year,
                           String description,
                           String empComments,
                           String mgrFeedback,
                           String mgrPrivateNotes,
                           Integer empOverallRating,
                           Integer mgrOverallRating,
                           String status) {
        this.goalId = goalId;
        this.employeeId = employeeId;
        this.goalName = goalName;
        this.year = year;
        this.description = description;
        this.empComments = empComments;
        this.mgrFeedback = mgrFeedback;
        this.mgrPrivateNotes = mgrPrivateNotes;
        this.empOverallRating = empOverallRating;
        this.mgrOverallRating = mgrOverallRating;
        this.status = status;
    }

    public Long getGoalId() {
        return goalId;
    }

    public void setGoalId(Long goalId) {
        this.goalId = goalId;
    }

    public Long getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(Long employeeId) {
        this.employeeId = employeeId;
    }

    public String getGoalName() {
        return goalName;
    }

    public void setGoalName(String goalName) {
        this.goalName = goalName;
    }

    public Integer getYear() {
        return year;
    }

    public void setYear(Integer year) {
        this.year = year;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getEmpComments() {
        return empComments;
    }

    public void setEmpComments(String empComments) {
        this.empComments = empComments;
    }

    public String getMgrFeedback() {
        return mgrFeedback;
    }

    public void setMgrFeedback(String mgrFeedback) {
        this.mgrFeedback = mgrFeedback;
    }

    public String getMgrPrivateNotes() {
        return mgrPrivateNotes;
    }

    public void setMgrPrivateNotes(String mgrPrivateNotes) {
        this.mgrPrivateNotes = mgrPrivateNotes;
    }

    public Integer getEmpOverallRating() {
        return empOverallRating;
    }

    public void setEmpOverallRating(Integer empOverallRating) {
        this.empOverallRating = empOverallRating;
    }

    public Integer getMgrOverallRating() {
        return mgrOverallRating;
    }

    public void setMgrOverallRating(Integer mgrOverallRating) {
        this.mgrOverallRating = mgrOverallRating;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }
}
