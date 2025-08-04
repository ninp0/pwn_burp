package com.pwn_burp.api.models;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import java.util.*;

public class ScanTask {
    private String host;
    private List<AuditIssue> issues = new ArrayList<>();
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

    // Getter and setter for requestCount
    public int getRequestCount() {
        return requestCount;
    }

    public void setRequestCount(int requestCount) {
        this.requestCount = requestCount;
    }
}
