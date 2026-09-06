package com.fikua.dss.dto.common;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ErrorResponse(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String errorDescription
) {}
