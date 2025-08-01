package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.pwn_burp.api.models.ScanIssue;

public class IssueService {
    private final MontoyaApi api;

    public IssueService(MontoyaApi api) {
        this.api = api;
    }

    public AuditIssue[] getScanIssues(String url) {
        return api.siteMap().issues().stream()
                .filter(issue -> url.isEmpty() || issue.httpService().host().equals(url))
                .toArray(AuditIssue[]::new);
    }

    public void addScanIssue(ScanIssue issue) {
        api.logging().logToOutput("Adding custom scan issues is not supported in Montoya API");
    }
}
