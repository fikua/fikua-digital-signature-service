package es.in2.mockqtsp.dto;

import java.util.List;

public record CscInfoResponse(
        String specs,
        String name,
        String logo,
        String region,
        String lang,
        String description,
        List<String> authType,
        List<String> methods
) {}
