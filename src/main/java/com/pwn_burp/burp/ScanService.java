package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.scanner.*;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.*;
import com.pwn_burp.api.handlers.*;
import com.pwn_burp.burp.Utils;
import java.io.File;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.net.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class ScanService {
    private final MontoyaApi api;
    private final ScopeService scopeService;
    private final IBurpExtenderCallbacks callbacks;
    private final Map<Integer, ScanEntry> scanQueue = new ConcurrentHashMap<>();
    private final Map<Integer, Long> scanStartTimes = new ConcurrentHashMap<>();
    private final Map<Integer, String> scanStatuses = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> lastIssueCounts = new ConcurrentHashMap<>();
    private final Map<Integer, Long> lastIssueUpdateTimes = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> lastPercentCompleteValue = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> lastRequestCounts = new ConcurrentHashMap<>();
    private final Map<Integer, Long> lastRequestUpdateTimes = new ConcurrentHashMap<>();
    private final AtomicInteger scanIdCounter = new AtomicInteger(0);
    private final AtomicInteger crawlIdCounter = new AtomicInteger(0);
    private final Map<Integer, Crawl> crawlMap = new ConcurrentHashMap<>();
    private final Map<Integer, Long> crawlStartTimes = new ConcurrentHashMap<>();
    private final Map<Integer, String> crawlStatuses = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> lastCrawlRequestCounts = new ConcurrentHashMap<>();
    private final Map<Integer, Long> lastCrawlRequestUpdateTimes = new ConcurrentHashMap<>();
    private final Map<Integer, String> crawlBaseUrls = new ConcurrentHashMap<>();
    private final Map<Integer, Integer> initialCrawlSizes = new ConcurrentHashMap<>();

    // Inner class to store IScanQueueItem and host metadata
    private static class ScanEntry {
        private final IScanQueueItem scanItem;
        private final String host;

        ScanEntry(IScanQueueItem scanItem, String host) {
            this.scanItem = scanItem;
            this.host = host;
        }

        IScanQueueItem getScanItem() {
            return scanItem;
        }

        String getHost() {
            return host;
        }
    }

    public ScanService(MontoyaApi api, ScopeService scopeService, IBurpExtenderCallbacks callbacks) {
        this.api = api;
        this.scopeService = scopeService;
        this.callbacks = callbacks;
        if (this.callbacks == null) {
            throw new IllegalArgumentException("IBurpExtenderCallbacks cannot be null");
        }
    }

    public int doActiveScan(String host, int port, boolean useHttps, byte[] request) {
        try {
            URI uri = new URI(useHttps ? "https" : "http", host, "/", null);
            URL url = uri.toURL();
            if (!scopeService.isInScope(url)) {
                api.logging().logToError("Target out of scope: " + url);
                return -1; // Indicate failure
            }
            IScanQueueItem scanItem = callbacks.doActiveScan(host, port, useHttps, request);
            if (scanItem != null) {
                int scanId = generateScanId();
                scanQueue.put(scanId, new ScanEntry(scanItem, host));
                scanStartTimes.put(scanId, System.currentTimeMillis());
                scanStatuses.put(scanId, "queued");
                lastIssueCounts.put(scanId, 0);
                lastPercentCompleteValue.put(scanId, 0);
                lastRequestCounts.put(scanId, 0);
                // Started active scan ID for url
                api.logging().logToOutput("Started active scan ID " + scanId + " for " + url);
                return scanId; // Return the assigned scanId
            }
            return -1; // Indicate failure if scanItem is null
        } catch (Exception e) {
            api.logging().logToError("Active scan failed: " + e.getMessage());
            throw new RuntimeException("Failed to perform active scan", e);
        }
    }

    public void doPassiveScan(String host, int port, boolean useHttps, byte[] request, byte[] response) {
        try {
            URI uri = new URI(useHttps ? "https" : "http", host, "/", null);
            URL url = uri.toURL();
            callbacks.doPassiveScan(host, port, useHttps, request, response);
            return;
        } catch (Exception e) {
            api.logging().logToError("Passive scan failed: " + e.getMessage());
            throw new RuntimeException("Failed to perform passive scan", e);
        }
    }

    public synchronized int generateScanId() {
        return scanIdCounter.incrementAndGet();
    }

    public int getScanQueueSize() {
        return scanQueue.size();
    }

    @SuppressWarnings("deprecation")
    public String getActiveScanStatus() {
        JsonArray items = new JsonArray();
        scanQueue.forEach((id, entry) -> {
            JsonObject obj = new JsonObject();
            obj.addProperty("id", id);
            String host = entry.getHost();
            IScanQueueItem scanItem = entry.getScanItem();
            // Get issues for the host using Montoya API
            AuditIssue[] issues = api.siteMap().issues().stream()
                    .filter(issue -> issue.httpService() != null && issue.httpService().host().equals(host))
                    .toArray(AuditIssue[]::new);
            obj.add("issues", Utils.scanIssuesToJsonArray(issues));
            Long startTime = scanStartTimes.get(id);
            String status = scanStatuses.getOrDefault(id, "queued");
            // Convert byte to int (0-100)
            int percentComplete = Byte.toUnsignedInt(scanItem.getPercentageComplete());
            int issueCount = issues.length;
            int requestCount = scanItem.getNumRequests();
            int insertionPointCount = scanItem.getNumInsertionPoints();
            int oldIssueCount = lastIssueCounts.getOrDefault(id, 0);
            int lastPercentComplete = lastPercentCompleteValue.getOrDefault(id, 0);
            int oldRequestCount = lastRequestCounts.getOrDefault(id, 0);
            Long lastIssueUpdate = lastIssueUpdateTimes.get(id);
            Long lastRequestUpdate = lastRequestUpdateTimes.get(id);
            String scanStatus = scanItem.getStatus();

            if (startTime != null) {
                long elapsed = System.currentTimeMillis() - startTime;
                // Update issue and request counts if changed
                if (issueCount != oldIssueCount) {
                    lastIssueCounts.put(id, issueCount);
                    lastIssueUpdateTimes.put(id, System.currentTimeMillis());
                    lastIssueUpdate = System.currentTimeMillis();
                }
                if (requestCount != oldRequestCount) {
                    lastRequestCounts.put(id, requestCount);
                    lastRequestUpdateTimes.put(id, System.currentTimeMillis());
                    lastRequestUpdate = System.currentTimeMillis();
                }
                // Consider scan finished if Burp status is "finished" or progress is 100%
                if (scanStatus.equalsIgnoreCase("finished") || percentComplete >= 100) {
                    status = "finished";
                    percentComplete = 100;
                } else if (elapsed > 60000 && issueCount == 0 && requestCount == 0) {
                    status = "failed";
                    percentComplete = 0;
                } else {
                    status = "running";
                    // Use getPercentageComplete if non-zero, else estimate
                    if (percentComplete == 0) {
                        percentComplete = Math.min(99, (int) (elapsed / 600)); // 1% per second
                    }
                    scanStatuses.put(id, status);
                }
                if (percentComplete != lastPercentComplete) {
                    lastPercentCompleteValue.put(id, percentComplete);
		    api.logging().logToOutput("Scan ID " + id + " percent complete updated: " + percentComplete + "%");
		}
            }
            obj.addProperty("error_count", scanItem.getNumErrors());
            obj.addProperty("insertion_point_count", insertionPointCount);
            obj.addProperty("request_count", requestCount);
            obj.addProperty("percent_complete", percentComplete);
            obj.addProperty("status", status);
            items.add(obj);
        });
        String result = items.toString();

        return result;
    }

    @SuppressWarnings("deprecation")
    public String getActiveScanById(int id) {
        ScanEntry entry = scanQueue.get(id);
        if (entry == null) {
            JsonObject obj = new JsonObject();
            obj.addProperty("id", id);
            obj.addProperty("status", "not_found");
            obj.addProperty("error_count", 0);
            obj.addProperty("insertion_point_count", 0);
            obj.addProperty("request_count", 0);
            obj.addProperty("percent_complete", 0);
            obj.add("issues", new JsonArray());
            api.logging().logToOutput("Scan ID " + id + " not found");
            return obj.toString();
        }
        String host = entry.getHost();
        IScanQueueItem scanItem = entry.getScanItem();
        JsonObject obj = new JsonObject();
        obj.addProperty("id", id);
        AuditIssue[] issues = api.siteMap().issues().stream()
                .filter(issue -> issue.httpService() != null && issue.httpService().host().equals(host))
                .toArray(AuditIssue[]::new);
        obj.add("issues", Utils.scanIssuesToJsonArray(issues));
        Long startTime = scanStartTimes.get(id);
        String status = scanStatuses.getOrDefault(id, "queued");
        // Convert byte to int (0-100)
        int percentComplete = Byte.toUnsignedInt(scanItem.getPercentageComplete());
        int issueCount = issues.length;
        int requestCount = scanItem.getNumRequests();
        int insertionPointCount = scanItem.getNumInsertionPoints();
        int oldIssueCount = lastIssueCounts.getOrDefault(id, 0);
        int lastPercentComplete = lastPercentCompleteValue.getOrDefault(id, 0);
        int oldRequestCount = lastRequestCounts.getOrDefault(id, 0);
        Long lastIssueUpdate = lastIssueUpdateTimes.get(id);
        Long lastRequestUpdate = lastRequestUpdateTimes.get(id);
        String scanStatus = scanItem.getStatus();

        if (startTime != null) {
            long elapsed = System.currentTimeMillis() - startTime;
            if (issueCount != oldIssueCount) {
                lastIssueCounts.put(id, issueCount);
                lastIssueUpdateTimes.put(id, System.currentTimeMillis());
                lastIssueUpdate = System.currentTimeMillis();
            }
            if (requestCount != oldRequestCount) {
                lastRequestCounts.put(id, requestCount);
                lastRequestUpdateTimes.put(id, System.currentTimeMillis());
                lastRequestUpdate = System.currentTimeMillis();
            }
            if (scanStatus.equalsIgnoreCase("finished") || percentComplete >= 100) {
                status = "finished";
                percentComplete = 100;
            } else if (elapsed > 60000 && issueCount == 0 && requestCount == 0) {
                status = "failed";
                percentComplete = 0;
            } else {
                status = "running";
                if (percentComplete == 0) {
                    percentComplete = Math.min(99, (int) (elapsed / 600));
                }
                scanStatuses.put(id, status);
            }
            if (percentComplete != lastPercentComplete) {
                lastPercentCompleteValue.put(id, percentComplete);
                api.logging().logToOutput("Scan ID " + id + " percent complete updated: " + percentComplete + "%");
            }
        }

        obj.addProperty("error_count", scanItem.getNumErrors());
        obj.addProperty("insertion_point_count", insertionPointCount);
        obj.addProperty("request_count", requestCount);
        obj.addProperty("percent_complete", percentComplete);
        obj.addProperty("status", status);

        return obj.toString();
    }

    public boolean cancelActiveScan(int id) {
        ScanEntry entry = scanQueue.remove(id);
        if (entry == null) {
            api.logging().logToOutput("Cannot cancel scan; ID not found: " + id);
            return false;
        }
        IScanQueueItem scanItem = entry.getScanItem();
        scanItem.cancel();
        scanStartTimes.remove(id);
        scanStatuses.remove(id);
        lastIssueCounts.remove(id);
        lastPercentCompleteValue.remove(id);
        lastIssueUpdateTimes.remove(id);
        lastRequestCounts.remove(id);
        lastRequestUpdateTimes.remove(id);
        api.logging().logToOutput("Active scan cancelled for ID: " + id);
        return true;
    }

    public String generateScanReport(String host, String reportType) {
        try {
            // Validate report type
            if (!reportType.equalsIgnoreCase("HTML") && !reportType.equalsIgnoreCase("XML")) {
                api.logging().logToError("Invalid report type: " + reportType);
                return "{\"error\":\"Invalid report type: " + reportType + "\"}";
            }

            // Get issues for the host
            AuditIssue[] auditIssues = api.siteMap().issues().stream()
                    .filter(issue -> issue.httpService() != null && issue.httpService().host().equals(host))
                    .toArray(AuditIssue[]::new);

            // Log issue count for debugging
            api.logging().logToOutput("Found " + auditIssues.length + " issues for host: " + host);

            // Convert reportType to ReportFormat
            ReportFormat format = reportType.equalsIgnoreCase("HTML") ? ReportFormat.HTML : ReportFormat.XML;

            // Generate report to a temporary file
            Path tempFile = Files.createTempFile("burp_report_", "." + reportType.toLowerCase());
            api.scanner().generateReport(Arrays.asList(auditIssues), format, tempFile);

            // Read report content
            String reportContent = Files.readString(tempFile, StandardCharsets.UTF_8);

            // Clean up
            Files.delete(tempFile);

            api.logging().logToOutput("Generated " + reportType + " report for host: " + host);
            return reportContent;
        } catch (Exception e) {
            api.logging().logToError("Report generation failed for host " + host + ": " + e.getMessage(), e);
            return "{\"error\":\"Report generation failed: " + e.getMessage() + "\"}";
        }
    }

    public int doCrawl(String url) {
        try {
            URL parsedUrl = URI.create(url).toURL();
            if (!scopeService.isInScope(parsedUrl)) {
                api.logging().logToError("Target out of scope: " + url);
                return -1;
            }
            CrawlConfiguration config = CrawlConfiguration.crawlConfiguration(url);
            Crawl crawl = api.scanner().startCrawl(config);
            int crawlId = crawlIdCounter.incrementAndGet();
            crawlMap.put(crawlId, crawl);
            crawlStartTimes.put(crawlId, System.currentTimeMillis());
            crawlStatuses.put(crawlId, "queued");
            lastCrawlRequestCounts.put(crawlId, 0);
            lastCrawlRequestUpdateTimes.put(crawlId, System.currentTimeMillis());
            return crawlId;
        } catch (Exception e) {
            api.logging().logToError("Crawl failed: " + e.getMessage());
            throw new RuntimeException("Failed to perform crawl", e);
        }
    }

    public String getCrawlStatus() {
        JsonArray items = new JsonArray();
        crawlMap.forEach((id, crawl) -> {
            JsonObject obj = new JsonObject();
            obj.addProperty("id", id);
            String baseUrl = crawlBaseUrls.get(id);
            int requestCount = 0;
            if (baseUrl != null) {
                List<HttpRequestResponse> siteMapItems = api.siteMap().requestResponses(SiteMapFilter.prefixFilter(baseUrl));
                int currentSize = siteMapItems.size();
                int initialSize = initialCrawlSizes.getOrDefault(id, 0);
                requestCount = currentSize - initialSize;
            }
            int errorCount = 0; // Unable to track accurately, default to 0
            String status = crawlStatuses.getOrDefault(id, "queued");
            Long startTime = crawlStartTimes.get(id);
            int oldRequestCount = lastCrawlRequestCounts.getOrDefault(id, 0);
            long lastUpdateTime = lastCrawlRequestUpdateTimes.getOrDefault(id, 0L);
            if (startTime != null) {
                long elapsed = System.currentTimeMillis() - startTime;
                if (requestCount != oldRequestCount) {
                    lastCrawlRequestCounts.put(id, requestCount);
                    lastCrawlRequestUpdateTimes.put(id, System.currentTimeMillis());
                    lastUpdateTime = System.currentTimeMillis();
                }
                long idleTime = System.currentTimeMillis() - lastUpdateTime;
                if (idleTime > 30000 && requestCount > 0) {
                    status = "finished";
                } else if (elapsed > 60000 && requestCount == 0) {
                    status = "failed";
                } else {
                    status = "running";
                }
                crawlStatuses.put(id, status);
            }
            obj.addProperty("request_count", requestCount);
            obj.addProperty("error_count", errorCount);
            obj.addProperty("status", status);
            items.add(obj);
        });
        return items.toString();
    }

    public String getCrawlById(int id) {
        Crawl crawl = crawlMap.get(id);
        if (crawl == null) {
            return "{\"status\":\"not_found\"}";
        }
        JsonObject obj = new JsonObject();
        String baseUrl = crawlBaseUrls.get(id);
        int requestCount = 0;
        if (baseUrl != null) {
            List<HttpRequestResponse> siteMapItems = api.siteMap().requestResponses(SiteMapFilter.prefixFilter(baseUrl));
            int currentSize = siteMapItems.size();
            int initialSize = initialCrawlSizes.getOrDefault(id, 0);
            requestCount = currentSize - initialSize;
        }
        int errorCount = 0; // Unable to track accurately, default to 0
        String status = crawlStatuses.getOrDefault(id, "queued");
        Long startTime = crawlStartTimes.get(id);
        int oldRequestCount = lastCrawlRequestCounts.getOrDefault(id, 0);
        long lastUpdateTime = lastCrawlRequestUpdateTimes.getOrDefault(id, 0L);
        if (startTime != null) {
            long elapsed = System.currentTimeMillis() - startTime;
            if (requestCount != oldRequestCount) {
                lastCrawlRequestCounts.put(id, requestCount);
                lastCrawlRequestUpdateTimes.put(id, System.currentTimeMillis());
                lastUpdateTime = System.currentTimeMillis();
            }
            long idleTime = System.currentTimeMillis() - lastUpdateTime;
            if (idleTime > 30000 && requestCount > 0 || elapsed > 60000 && requestCount == 0) {
                status = "finished";
            } else {
                status = "running";
            }
            crawlStatuses.put(id, status);
        }
        api.logging().logToOutput("Crawl ID " + id + " discovered: " + requestCount + ", status: " + status);
        obj.addProperty("request_count", requestCount);
        obj.addProperty("error_count", errorCount);
        obj.addProperty("status", status);
        return obj.toString();
    }

/*
    // TODO: Use these methods once crawl.requestCount() and crawl.errorCount() are available in Montoya API
    public String getCrawlStatus() {
        JsonArray items = new JsonArray();
        crawlMap.forEach((id, crawl) -> {
            JsonObject obj = new JsonObject();
            obj.addProperty("id", id);
            int requestCount = crawl.requestCount();
            int errorCount = crawl.errorCount();
            String status = crawlStatuses.getOrDefault(id, "queued");
            Long startTime = crawlStartTimes.get(id);
            int oldRequestCount = lastCrawlRequestCounts.getOrDefault(id, 0);
            long lastUpdateTime = lastCrawlRequestUpdateTimes.getOrDefault(id, 0L);
            if (startTime != null) {
                long elapsed = System.currentTimeMillis() - startTime;
                if (requestCount != oldRequestCount) {
                    lastCrawlRequestCounts.put(id, requestCount);
                    lastCrawlRequestUpdateTimes.put(id, System.currentTimeMillis());
                    lastUpdateTime = System.currentTimeMillis();
                }
                long idleTime = System.currentTimeMillis() - lastUpdateTime;
                if (idleTime > 30000 && requestCount > 0) {
                    status = "finished";
                } else if (elapsed > 60000 && requestCount == 0) {
                    status = "failed";
                } else {
                    status = "running";
                }
                crawlStatuses.put(id, status);
            }
            obj.addProperty("request_count", requestCount);
            obj.addProperty("error_count", errorCount);
            obj.addProperty("status", status);
            items.add(obj);
        });
        return items.toString();
    }

    public String getCrawlById(int id) {
        Crawl crawl = crawlMap.get(id);
        if (crawl == null) {
            return "{\"status\":\"not_found\"}";
        }
        JsonObject obj = new JsonObject();
        int requestCount = crawl.requestCount();
        int errorCount = crawl.errorCount();
        String status = crawlStatuses.getOrDefault(id, "queued");
        Long startTime = crawlStartTimes.get(id);
        int oldRequestCount = lastCrawlRequestCounts.getOrDefault(id, 0);
        long lastUpdateTime = lastCrawlRequestUpdateTimes.getOrDefault(id, 0L);
        if (startTime != null) {
            long elapsed = System.currentTimeMillis() - startTime;
            if (requestCount != oldRequestCount) {
                lastCrawlRequestCounts.put(id, requestCount);
                lastCrawlRequestUpdateTimes.put(id, System.currentTimeMillis());
                lastUpdateTime = System.currentTimeMillis();
            }
            long idleTime = System.currentTimeMillis() - lastUpdateTime;
            if (idleTime > 30000 && requestCount > 0) {
                status = "finished";
            } else if (elapsed > 60000 && requestCount == 0) {
                status = "failed";
            } else {
                status = "running";
            }
            crawlStatuses.put(id, status);
        }
        api.logging().logToOutput("Crawl ID " + id + " request count: " + requestCount + ", status: " + status);
        obj.addProperty("request_count", requestCount);
        obj.addProperty("error_count", errorCount);
        obj.addProperty("status", status);
        return obj.toString();
    }
*/

    public boolean cancelCrawl(int id) {
        Crawl crawl = crawlMap.remove(id);
        if (crawl == null) {
            return false;
        }
        crawl.delete();
        crawlStartTimes.remove(id);
        crawlStatuses.remove(id);
        lastCrawlRequestCounts.remove(id);
        lastCrawlRequestUpdateTimes.remove(id);
        return true;
    }
}
