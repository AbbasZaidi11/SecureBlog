package org.example.dtos;

import java.util.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data // generates getters, setters, toString, equals, and hashCode
@Builder // allows building objects using builder pattern
@NoArgsConstructor // generates default empty constructor
@AllArgsConstructor // generates constructor with all fields
public class ApiErrorResponse {

    // HTTP status code (e.g., 400, 404, 500)
    private int status;

    // General message about the error (e.g., "Validation failed", "User not found")
    private String message;

    // List of specific field-level errors (used mainly for validation failures)
    private List<FieldError> errors;

    /**
     * Nested static class to represent a validation error for a specific field.
     * Example: field = "email", message = "Email is invalid"
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class FieldError {
        // Name of the field that has the error (ex: "title", "password")
        private String field;

        // Error message explaining what went wrong for that field
        private String message;
    }
}
