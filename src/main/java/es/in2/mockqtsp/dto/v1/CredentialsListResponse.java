package es.in2.mockqtsp.dto.v1;

import java.util.List;

public record CredentialsListResponse(
        List<String> credentialIDs,
        String nextPageToken
) {}
