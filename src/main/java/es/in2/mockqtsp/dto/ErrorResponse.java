package es.in2.mockqtsp.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ErrorResponse(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription
) {}
