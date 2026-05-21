package com.fikua.dss.dto;

public record TokenRequest(
        String grant_type,
        String scope,
        String authorization_details
) {}