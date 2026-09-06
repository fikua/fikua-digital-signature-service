package com.fikua.dss.dto.v2;

import java.util.List;

public record KeyInfo(String status, List<String> algo, int len) {}
