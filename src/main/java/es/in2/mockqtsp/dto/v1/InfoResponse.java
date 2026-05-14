package es.in2.mockqtsp.dto.v1;

import java.util.List;

public record InfoResponse(
        String specs,
        String name,
        String logo,
        String region,
        String lang,
        String description,
        List<String> authType,
        String oauth2,
        List<String> methods
) {}
