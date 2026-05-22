package example.hrdemo.model;

import io.micronaut.serde.annotation.Serdeable;

import java.math.BigDecimal;

@Serdeable
public record Employee(Long employeeId,
                       String firstName,
                       String lastName,
                       BigDecimal salary) {
}
