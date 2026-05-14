package es.in2.mockqtsp.dto.v1;

public record CredentialsListRequest(
        String userID,
        Integer maxResults,
        String pageToken,
        String clientData
) {}
