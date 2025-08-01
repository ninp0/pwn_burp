package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.pwn_burp.api.handlers.*;
import com.pwn_burp.api.models.*;
import java.net.URL;
import java.util.List;

public class PwnService {
    private final MontoyaApi api;
    private final ScanService scanService;
    private final ProxyService proxyService;
    private final ScopeService scopeService;
    private final SiteMapService siteMapService;
    private final IssueService issueService;
    private final ToolService toolService;

    public PwnService(MontoyaApi api, IBurpExtenderCallbacks callbacks) {
        this.api = api;
        this.scopeService = new ScopeService(api);
        this.scanService = new ScanService(api, scopeService, callbacks);
        this.proxyService = new ProxyService(api, callbacks);
        this.siteMapService = new SiteMapService(api);
        this.issueService = new IssueService(api);
        this.toolService = new ToolService(api);
    }

    public Logging getLogging() {
        return api.logging();
    }

    public int generateScanId() {
        return scanService.generateScanId();
    }

    //public void addToScanQueue(int id, ScanTask task) {
    //    scanService.addToScanQueue(id, task);
    //}

    public int getScanQueueSize() {
        return scanService.getScanQueueSize();
    }

    public String getActiveScanStatus() {
        return scanService.getActiveScanStatus();
    }

    public String getActiveScanById(int id) {
        return scanService.getActiveScanById(id);
    }

    public boolean cancelActiveScan(int id) {
        return scanService.cancelActiveScan(id);
    }

    public int doActiveScan(String host, int port, boolean useHttps, byte[] request) {
        return scanService.doActiveScan(host, port, useHttps, request);
    }

    public void doPassiveScan(String host, int port, boolean useHttps, byte[] request, byte[] response) {
        scanService.doPassiveScan(host, port, useHttps, request, response);
    }

    public String generateScanReport(String host, String reportType) {
        return scanService.generateScanReport(host, reportType);
    }

    public String getProxyHistory() {
        return proxyService.getProxyHistory();
    }

    public void setProxyInterceptionEnabled(boolean enabled) {
        proxyService.setProxyInterceptionEnabled(enabled);
    }

    public List<IProxyListener> getProxyListeners() {
        return proxyService.getProxyListeners();
    }

    public boolean addProxyListener(String bindAddress, int port) {
        return proxyService.addProxyListener(bindAddress, port);
    }

    public boolean updateProxyListener(String id, String bindAddress, int port) {
        return proxyService.updateProxyListener(id, bindAddress, port);
    }

    public boolean deleteProxyListener(String id) {
        return proxyService.deleteProxyListener(id);
    }

    public boolean isInScope(URL url) {
        return scopeService.isInScope(url);
    }

    public void includeInScope(URL url) {
        scopeService.includeInScope(url);
    }

    public void excludeFromScope(URL url) {
        scopeService.excludeFromScope(url);
    }

    public String getSiteMap(String urlPrefix) {
        return siteMapService.getSiteMap(urlPrefix);
    }

    public void addToSiteMap(SiteMapMessage message) {
        siteMapService.addToSiteMap(message);
    }

    public AuditIssue[] getScanIssues(String url) {
        return issueService.getScanIssues(url);
    }

    public void addScanIssue(ScanIssue issue) {
        issueService.addScanIssue(issue);
    }

    public void sendToSpider(URL url) {
        toolService.sendToSpider(url);
    }

    public void sendToIntruder(String host, int port, boolean useHttps, byte[] request) {
        toolService.sendToIntruder(host, port, useHttps, request);
    }

    public void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabName) {
        toolService.sendToRepeater(host, port, useHttps, request, tabName);
    }

    public void issueAlert(String message) {
        api.logging().logToOutput("Alert: " + message);
    }

    public void updateCookieJar(Cookie cookie) {
        api.logging().logToOutput("Cookie jar updates are not supported in Montoya API");
    }

    public JsonObject apiError(String field, String message) {
        return Utils.apiError(field, message);
    }

    public JsonArray scanIssuesToJsonArray(AuditIssue[] issues) {
        return Utils.scanIssuesToJsonArray(issues);
    }

    public boolean isNotSameOrigin(String host, String origin) {
        return Utils.isNotSameOrigin(host, origin);
    }
}
