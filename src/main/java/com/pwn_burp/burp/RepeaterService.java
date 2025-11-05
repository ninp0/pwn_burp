package com.pwn_burp.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.pwn_burp.api.models.RepeaterItem;
import com.pwn_burp.api.models.RepeaterMessage;
import com.pwn_burp.api.models.RepeaterResponse;

import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class RepeaterService {
    private final MontoyaApi api;
    private final Map<Integer, RepeaterItem> items = new HashMap<>();
    private final AtomicInteger idGenerator = new AtomicInteger(1);

    public RepeaterService(MontoyaApi api) {
        this.api = api;
    }

    public int createItem(String name, String requestBase64) {
        int id = idGenerator.getAndIncrement();
        RepeaterItem item = new RepeaterItem();
        item.id = id;
        item.name = name;
        item.request = requestBase64;
        item.response = null;
        items.put(id, item);

        // Send to Burp Repeater tab
        HttpRequest httpRequest = createHttpRequest(requestBase64);
        api.repeater().sendToRepeater(httpRequest, name);

        return id;
    }

    public List<RepeaterItem> getItems() {
        return new ArrayList<>(items.values());
    }

    public RepeaterItem getItem(int id) {
        return items.get(id);
    }

    public boolean updateItem(int id, String name, String requestBase64) {
        RepeaterItem item = items.get(id);
        if (item == null) {
            return false;
        }
        if (name != null) {
            item.name = name;
        }
        if (requestBase64 != null) {
            item.request = requestBase64;
        }
        // Note: Cannot update the existing Repeater tab via Montoya API
        return true;
    }

    public boolean deleteItem(int id) {
        // Cannot delete the corresponding Repeater tab via API
        return items.remove(id) != null;
    }

    public RepeaterResponse sendItem(int id) {
        RepeaterItem item = items.get(id);
        if (item == null) {
            return null;
        }
        HttpRequest httpRequest = createHttpRequest(item.request);
        HttpRequestResponse rr = api.http().sendRequest(httpRequest);

        RepeaterResponse resp = new RepeaterResponse();
        resp.request = Base64.getEncoder().encodeToString(rr.request().toByteArray().getBytes());
        resp.response = Base64.getEncoder().encodeToString(rr.response().toByteArray().getBytes());
        item.response = resp.response;
        return resp;
    }

    @SuppressWarnings("deprecation")
    private HttpRequest createHttpRequest(String requestBase64) {
        byte[] requestBytes;
        try {
            requestBytes = Base64.getDecoder().decode(requestBase64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid base64 in request");
        }

        String requestString = new String(requestBytes);
        int headerEnd = requestString.indexOf("\r\n\r\n");
        if (headerEnd == -1) {
            headerEnd = requestString.indexOf("\n\n");
        }
        String headersStr = headerEnd >= 0 ? requestString.substring(0, headerEnd) : requestString;
        String[] headerLines = headersStr.split("\r?\n");
        String requestLine = headerLines[0];
        String[] rlParts = requestLine.split("\\s+", 3);
        if (rlParts.length < 2) {
            throw new IllegalArgumentException("Invalid request line");
        }
        String target = rlParts[1];

        HttpService service;
        byte[] finalRequestBytes = requestBytes;

        if (target.startsWith("http://") || target.startsWith("https://")) {
            URL url;
            try {
                url = new URL(target);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid URL in request line: " + e.getMessage());
            }
            String host = url.getHost();
            int port = url.getPort();
            String protocol = url.getProtocol();
            boolean secure = protocol.equalsIgnoreCase("https");
            if (port == -1) {
                port = secure ? 443 : 80;
            }
            service = HttpService.httpService(host, port, secure);

            // Normalize to relative URI
            String path = url.getFile();
            if (url.getRef() != null) {
                path += "#" + url.getRef();
            }
            StringBuilder newRequest = new StringBuilder();
            newRequest.append(rlParts[0]).append(" ").append(path);
            if (rlParts.length > 2) {
                newRequest.append(" ").append(rlParts[2]);
            }
            newRequest.append("\r\n");

            boolean hasHost = false;
            for (int i = 1; i < headerLines.length; i++) {
                String line = headerLines[i];
                if (line.toLowerCase().startsWith("host:")) {
                    hasHost = true;
                    newRequest.append("Host: ").append(host);
                    if (port != (secure ? 443 : 80)) {
                        newRequest.append(":").append(port);
                    }
                    newRequest.append("\r\n");
                } else {
                    newRequest.append(line).append("\r\n");
                }
            }
            if (!hasHost) {
                newRequest.append("Host: ").append(host);
                if (port != (secure ? 443 : 80)) {
                    newRequest.append(":").append(port);
                }
                newRequest.append("\r\n");
            }
            newRequest.append("\r\n");

            if (headerEnd >= 0) {
                String body = requestString.substring(headerEnd + (requestString.startsWith("\r\n\r\n", headerEnd) ? 4 : 2));
                newRequest.append(body);
            }

            finalRequestBytes = newRequest.toString().getBytes();
        } else {
            // Relative URI, parse from Host header
            String hostHeader = null;
            for (String line : headerLines) {
                if (line.toLowerCase().startsWith("host:")) {
                    hostHeader = line.substring(5).trim();
                    break;
                }
            }
            if (hostHeader == null) {
                throw new IllegalArgumentException("No Host header in request");
            }
            String host;
            int port = -1;
            boolean secure = true; // Assume HTTPS
            if (hostHeader.contains(":")) {
                String[] parts = hostHeader.split(":", 2);
                host = parts[0];
                try {
                    port = Integer.parseInt(parts[1]);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid port in Host header");
                }
            } else {
                host = hostHeader;
            }
            if (port == -1) {
                port = 443;
            }
            service = HttpService.httpService(host, port, secure);
        }

        return HttpRequest.httpRequest(service, ByteArray.byteArray(finalRequestBytes));
    }
}
