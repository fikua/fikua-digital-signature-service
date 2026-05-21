package com.fikua.dss.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record SignDocResponse(
        @JsonProperty("DocumentWithSignature") List<String> documentWithSignature
) {}
