package com.pwn_burp.api.models;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import java.util.*;
import com.google.gson.annotations.SerializedName;

public class ScanTask {
    @SerializedName("host")
    private String host;
    @SerializedName("issues")
    private List<AuditIssue> issues = new ArrayList<>();
    @SerializedName("requestCount")
    private int requestCount = 0;

    // Getter and setter for host
    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public AuditIssue[] getIssues() {
        return issues.toArray(new AuditIssue[0]);
    }

    public void addIssue(AuditIssue issue) {
        issues.add(issue);
    }
}
