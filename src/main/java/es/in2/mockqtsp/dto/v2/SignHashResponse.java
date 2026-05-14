package es.in2.mockqtsp.dto.v2;

import java.util.List;

public record SignHashResponse(
        List<String> signatures,
        String responseID
) {}
