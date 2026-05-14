package es.in2.mockqtsp.dto.v2;

import java.util.List;

public record Auth(
        String mode,
        String expression,
        List<AuthObject> objects
) {
    public record AuthObject(
            String type,
            String id,
            String format,
            String generator,
            String label,
            String description
    ) {}
}
