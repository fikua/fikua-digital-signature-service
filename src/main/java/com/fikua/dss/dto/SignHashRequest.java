package com.fikua.dss.dto;

import java.util.List;

public record SignHashRequest(
        String credentialID,
        String SAD,
        List<String> hash,
        String hashAlgo,
        String signAlgo
) {}
