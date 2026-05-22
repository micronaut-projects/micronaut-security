package example.hrdemo.controllers;

import example.hrdemo.model.Employee;
import example.hrdemo.repositories.EmployeeRepository;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

import java.security.Principal;
import java.util.Optional;

@Controller("/employee")
class EmployeeController {
    private final EmployeeRepository employeeRepository;

    EmployeeController(EmployeeRepository employeeRepository) {
        this.employeeRepository = employeeRepository;
    }

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @Get("/{employeeId}")
    Optional<Employee> show(Principal principal, @PathVariable("employeeId") Long employeeId) {
        return employeeRepository.findById(principal, employeeId);
    }
}
