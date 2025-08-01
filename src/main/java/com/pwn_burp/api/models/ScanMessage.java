package com.pwn_burp.api.models;

import com.google.gson.annotations.SerializedName;

public class ScanMessage {
    @SerializedName("host")
    public final String host;

    @SerializedName("port")
    public final int port;

    @SerializedName("use_https")
    public final boolean useHttps;

    @SerializedName("request")
    public final String request;

    @SerializedName("response")
    public final String response;

    // Constructor for active scan (no response)
    public ScanMessage(String host, int port, boolean useHttps, String request) {
        this(host, port, useHttps, request, null);
    }

    // Constructor for passive scan (with response)
    public ScanMessage(String host, int port, boolean useHttps, String request, String response) {
        this.host = host;
        this.port = port;
        this.useHttps = useHttps;
        this.request = request;
        this.response = response;
    }
}
