package com.fikua.dss.admin;

/** Who is using the administration API: the subject of its token. */
public record Administrator(String id, String name) {}
