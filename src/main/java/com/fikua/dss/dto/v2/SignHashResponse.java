package com.fikua.dss.dto.v2;

import java.util.List;

public record SignHashResponse(
        List<String> signatures,
        String responseID
) {}
