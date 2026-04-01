package es.in2.mockqtsp.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record SignDocResponse(
        @JsonProperty("DocumentWithSignature") List<String> documentWithSignature
) {}
