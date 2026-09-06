package com.fikua.dss.dto.v1;

import java.util.List;

public record SignHashRequest(
        String credentialID,
        String SAD,
        List<String> hash,
        String hashAlgo,
        String signAlgo,
        String signAlgoParams,
        String clientData
) {}
