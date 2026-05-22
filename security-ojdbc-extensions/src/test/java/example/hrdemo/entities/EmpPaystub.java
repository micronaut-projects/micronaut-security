package example.hrdemo.entities;

import io.micronaut.data.annotation.Id;
import io.micronaut.data.annotation.MappedEntity;
import io.micronaut.data.annotation.MappedProperty;

import java.math.BigDecimal;
import java.time.LocalDate;

@MappedEntity("emp_paystubs")
public class EmpPaystub {

    @Id
    @MappedProperty("paystub_id")
    private Long paystubId;

    @MappedProperty("employee_id")
    private Long employeeId;

    @MappedProperty("pay_period_start")
    private LocalDate payPeriodStart;

    @MappedProperty("pay_period_end")
    private LocalDate payPeriodEnd;

    @MappedProperty("gross_pay")
    private BigDecimal grossPay;

    @MappedProperty("net_pay")
    private BigDecimal netPay;

    @MappedProperty("tax_withheld")
    private BigDecimal taxWithheld;

    private BigDecimal deductions;

    @MappedProperty("pay_date")
    private LocalDate payDate;

    @MappedProperty("bank_account")
    private String bankAccount;

    public EmpPaystub() {
    }

    public EmpPaystub(Long paystubId,
                      Long employeeId,
                      LocalDate payPeriodStart,
                      LocalDate payPeriodEnd,
                      BigDecimal grossPay,
                      BigDecimal netPay,
                      BigDecimal taxWithheld,
                      BigDecimal deductions,
                      LocalDate payDate,
                      String bankAccount) {
        this.paystubId = paystubId;
        this.employeeId = employeeId;
        this.payPeriodStart = payPeriodStart;
        this.payPeriodEnd = payPeriodEnd;
        this.grossPay = grossPay;
        this.netPay = netPay;
        this.taxWithheld = taxWithheld;
        this.deductions = deductions;
        this.payDate = payDate;
        this.bankAccount = bankAccount;
    }

    public Long getPaystubId() {
        return paystubId;
    }

    public void setPaystubId(Long paystubId) {
        this.paystubId = paystubId;
    }

    public Long getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(Long employeeId) {
        this.employeeId = employeeId;
    }

    public LocalDate getPayPeriodStart() {
        return payPeriodStart;
    }

    public void setPayPeriodStart(LocalDate payPeriodStart) {
        this.payPeriodStart = payPeriodStart;
    }

    public LocalDate getPayPeriodEnd() {
        return payPeriodEnd;
    }

    public void setPayPeriodEnd(LocalDate payPeriodEnd) {
        this.payPeriodEnd = payPeriodEnd;
    }

    public BigDecimal getGrossPay() {
        return grossPay;
    }

    public void setGrossPay(BigDecimal grossPay) {
        this.grossPay = grossPay;
    }

    public BigDecimal getNetPay() {
        return netPay;
    }

    public void setNetPay(BigDecimal netPay) {
        this.netPay = netPay;
    }

    public BigDecimal getTaxWithheld() {
        return taxWithheld;
    }

    public void setTaxWithheld(BigDecimal taxWithheld) {
        this.taxWithheld = taxWithheld;
    }

    public BigDecimal getDeductions() {
        return deductions;
    }

    public void setDeductions(BigDecimal deductions) {
        this.deductions = deductions;
    }

    public LocalDate getPayDate() {
        return payDate;
    }

    public void setPayDate(LocalDate payDate) {
        this.payDate = payDate;
    }

    public String getBankAccount() {
        return bankAccount;
    }

    public void setBankAccount(String bankAccount) {
        this.bankAccount = bankAccount;
    }
}
