package com.pwn_burp.api.models;

import com.google.gson.annotations.SerializedName;
import java.util.Objects;

public class SiteMapMessage {
    @SerializedName("request")
    private final String request; // Base64-encoded HTTP request

    @SerializedName("response")
    private final String response; // Base64-encoded HTTP response

    @SerializedName("highlight")
    private String highlight;

    @SerializedName("comment")
    private String comment;

    @SerializedName("http_service")
    private final HttpService httpService;

    public SiteMapMessage(String request, String response, String highlight, String comment, HttpService httpService) {
        this.request = request;
        this.response = response;
        this.highlight = highlight;
        this.comment = comment;
        this.httpService = httpService;
    }

    public String getRequest() {
        return request;
    }

    public String getResponse() {
        return response;
    }

    public String getHighlight() {
        return highlight;
    }

    public void setHighlight(String highlight) {
        this.highlight = highlight;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public HttpService getHttpService() {
        return httpService;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SiteMapMessage that = (SiteMapMessage) o;
        return Objects.equals(request, that.request) &&
               Objects.equals(response, that.response) &&
               Objects.equals(highlight, that.highlight) &&
               Objects.equals(comment, that.comment) &&
               Objects.equals(httpService, that.httpService);
    }

    @Override
    public int hashCode() {
        return Objects.hash(request, response, highlight, comment, httpService);
    }

    @Override
    public String toString() {
        return "SiteMapMessage{" +
               "  request='" + request + '\'' +
               ", response='" + response + '\'' +
               ", highlight='" + highlight + '\'' +
               ", comment='" + comment + '\'' +
               ", httpService=" + httpService +
               '}';
    }

    // Nested HttpService class
    public static class HttpService {
        @SerializedName("host")
        private final String host;

        @SerializedName("port")
        private final int port;

        @SerializedName("protocol")
        private final String protocol;

        public HttpService(String host, int port, String protocol) {
            this.host = host;
            this.port = port;
            this.protocol = protocol;
        }

        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

        public String getProtocol() {
            return protocol;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            HttpService that = (HttpService) o;
            return port == that.port &&
                   Objects.equals(host, that.host) &&
                   Objects.equals(protocol, that.protocol);
        }

        @Override
        public int hashCode() {
            return Objects.hash(host, port, protocol);
        }

        @Override
        public String toString() {
            return "HttpService{host='" + host + "', port=" + port + ", protocol='" + protocol + "'}";
        }
    }
}
