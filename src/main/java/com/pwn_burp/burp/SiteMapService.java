package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.sitemap.SiteMap;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.pwn_burp.api.models.SiteMapMessage;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class SiteMapService {
    private final MontoyaApi api;

    public SiteMapService(MontoyaApi api) {
        this.api = api;
    }

    public void addToSiteMap(SiteMapMessage message) {
        if (message == null || message.getRequest() == null) {
            api.logging().logToError("Invalid SiteMapMessage: request is required");
            throw new IllegalArgumentException("SiteMapMessage and request cannot be null");
        }

        try {
            // Decode Base64 request
            byte[] requestBytes = Base64.getDecoder().decode(message.getRequest());
            ByteArray requestByteArray = ByteArray.byteArray(requestBytes);

            // Construct HttpService from http_service
            SiteMapMessage.HttpService httpService = message.getHttpService();
            if (httpService == null || httpService.getHost() == null || httpService.getProtocol() == null) {
                api.logging().logToError("HttpService is required with host and protocol");
                throw new IllegalArgumentException("HttpService, host, and protocol cannot be null");
            }
            boolean secure = httpService.getProtocol().equalsIgnoreCase("https");
            HttpService montoyaHttpService = HttpService.httpService(httpService.getHost(), httpService.getPort(), secure);

            // Create HttpRequest
            HttpRequest httpRequest = HttpRequest.httpRequest(montoyaHttpService, requestByteArray);

            // Decode Base64 response (if provided)
            HttpResponse httpResponse = null;
            if (message.getResponse() != null && !message.getResponse().isEmpty()) {
                byte[] responseBytes = Base64.getDecoder().decode(message.getResponse());
                ByteArray responseByteArray = ByteArray.byteArray(responseBytes);
                httpResponse = HttpResponse.httpResponse(responseByteArray);
            }

            // Create Annotations object for comment and highlight
            Annotations annotations = Annotations.annotations();
            if (message.getComment() != null && !message.getComment().isEmpty()) {
                annotations = annotations.withNotes(message.getComment());
            }
            if (message.getHighlight() != null && !message.getHighlight().isEmpty() && !message.getHighlight().equals("NONE")) {
                try {
                    HighlightColor highlightColor = HighlightColor.valueOf(message.getHighlight().toUpperCase());
                    annotations = annotations.withHighlightColor(highlightColor);
                } catch (IllegalArgumentException e) {
                    api.logging().logToError("Invalid highlight color: " + message.getHighlight());
                    // Continue without setting highlight color
                }
            }

            // Create HttpRequestResponse object with annotations
            HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                httpRequest,
                httpResponse,
                annotations
            );

            // Add to sitemap
            api.siteMap().add(requestResponse);

            api.logging().logToOutput("Added sitemap entry for " + httpRequest.url() +
                                     " with comment: " + message.getComment() +
                                     ", highlight: " + message.getHighlight());
        } catch (IllegalArgumentException e) {
            api.logging().logToError("Failed to decode Base64 or create request/response: " + e.getMessage());
            throw new RuntimeException("Failed to add sitemap entry", e);
        } catch (Exception e) {
            api.logging().logToError("Failed to add sitemap entry: " + e.getMessage());
            throw new RuntimeException("Failed to add sitemap entry", e);
        }
    }

    public void updateSiteMap(SiteMapMessage message) {
      if (message == null || message.getRequest() == null) {
        api.logging().logToError("Invalid SiteMapMessage: request is required for update");
        throw new IllegalArgumentException("SiteMapMessage and request cannot be null for update");
      }

      try {
        // Decode Base64 request
        byte[] requestBytes = Base64.getDecoder().decode(message.getRequest());
        ByteArray requestByteArray = ByteArray.byteArray(requestBytes);

        // Find existing entry by matching request bytes
        Optional<HttpRequestResponse> existingEntryOpt = api.siteMap().requestResponses().stream()
        .filter(item -> item.request() != null && item.request().toByteArray().equals(requestByteArray))
        .findFirst();

        if (existingEntryOpt.isPresent()) {
          HttpRequestResponse existingEntry = existingEntryOpt.get();
          String notes = message.getComment();
          HighlightColor hl = HighlightColor.NONE;
          String color = message.getHighlight();
          try {
            hl = HighlightColor.valueOf(color.toUpperCase());
          } catch (IllegalArgumentException e) {
            api.logging().logToError("Invalid highlight color: " + color + ". Using NONE.");
            hl = HighlightColor.NONE;
          }

          // Update annotations
          Annotations annotations = existingEntry.annotations();
          annotations.setNotes(message.getComment());
          annotations.setHighlightColor(hl);
        } else {
          api.logging().logToError("No existing sitemap entry found for the provided request: " + message.getRequest());
          // throw new RuntimeException("No existing sitemap entry found for the provided request");
        }
      } catch (IllegalArgumentException e) {
        api.logging().logToError("Failed to decode Base64 or create request/response: " + e.getMessage());
        throw new RuntimeException("Failed to update sitemap entry", e);
      } catch (Exception e) {
        api.logging().logToError("Failed to update sitemap entry: " + e.getMessage());
throw new RuntimeException("Failed to update sitemap entry", e);
      }
    }

    /**
     * RESILIENT, PAGINATED getSiteMap — now returns MOST RECENT entries first.
     * offset=0 → newest 500 items (newest at index 0 of the JSON array).
     */
    public String getSiteMap(String urlPrefix, int limit, int offset) {
        final int MAX_LIMIT = 500;
        int effectiveLimit = Math.min(Math.max(limit, 1), MAX_LIMIT);
        int effectiveOffset = Math.max(0, offset);

        JsonArray maps = new JsonArray();
        int processed = 0;

        try {
            List<HttpRequestResponse> sitemap = api.siteMap().requestResponses();
            int total = sitemap.size();

            // Iterate from the end (newest first)
            for (int i = total - 1; i >= 0; i--) {
                HttpRequestResponse item = sitemap.get(i);

                if (processed < effectiveOffset) {
                    processed++;
                    continue;
                }

                if (maps.size() >= effectiveLimit) {
                    break;
                }

                // URL prefix filter
                if (!urlPrefix.isEmpty()) {
                    String url = (item.request() != null) ? item.request().url() : null;
                    if (url == null || !url.startsWith(urlPrefix)) {
                        continue;
                    }
                }

                try {
                    maps.add(createSiteMapEntry(item));
                } catch (Exception e) {
                    api.logging().logToError("Failed to process one sitemap entry: " + e.getMessage());
                }
                processed++;
            }
        } catch (Exception e) {
            api.logging().logToError("Critical error iterating sitemap for prefix '" + urlPrefix + "': " + e.getMessage());
        }

        return maps.toString();
    }

    /**
     * Helper that builds a single sitemap entry (always includes full bodies).
     */
    private JsonObject createSiteMapEntry(HttpRequestResponse item) {
        JsonObject obj = new JsonObject();

        // Timing data
        Optional<TimingData> timingDataOpt = item.timingData();
        if (timingDataOpt.isPresent()) {
            TimingData td = timingDataOpt.get();
            obj.addProperty("time_between_request_sent_and_start_of_response", td.timeBetweenRequestSentAndStartOfResponse().toMillis());
            obj.addProperty("time_between_request_sent_and_end_of_response", td.timeBetweenRequestSentAndEndOfResponse().toMillis());
            obj.addProperty("time_request_sent", td.timeRequestSent().toString());
        } else {
            obj.addProperty("time_between_request_sent_and_start_of_response", -1);
            obj.addProperty("time_between_request_sent_and_end_of_response", -1);
            obj.addProperty("time_request_sent", "");
        }

        // Full request/response bodies (ALWAYS included)
        String requestBase64 = item.request() != null
                ? Base64.getEncoder().encodeToString(item.request().toByteArray().getBytes()) : null;
        obj.addProperty("request", requestBase64);

        String responseBase64 = item.response() != null
                ? Base64.getEncoder().encodeToString(item.response().toByteArray().getBytes()) : null;
        obj.addProperty("response", responseBase64);

        // Annotations
        String highlight = (item.annotations() != null && item.annotations().highlightColor() != null)
                ? item.annotations().highlightColor().toString() : "";
        obj.addProperty("highlight", highlight);

        String comment = (item.annotations() != null && item.annotations().notes() != null)
                ? item.annotations().notes() : "";
        obj.addProperty("comment", comment);

        // HTTP Service
        JsonObject serviceObj = new JsonObject();
        HttpService httpService = item.httpService();
        serviceObj.addProperty("host", httpService != null && httpService.host() != null ? httpService.host() : "");
        serviceObj.addProperty("port", httpService != null ? httpService.port() : 0);
        serviceObj.addProperty("protocol", httpService != null ? (httpService.secure() ? "https" : "http") : "");
        obj.add("http_service", serviceObj);

        return obj;
    }

    /**
     * Backward-compatibility overload (used by old handlers that call getSiteMap(String) only).
     * Returns first 200 items with no prefix filter.
     */
    public String getSiteMap(String urlPrefix) {
        return getSiteMap(urlPrefix, 200, 0);
    }
}
