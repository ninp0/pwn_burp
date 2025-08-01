package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.net.URL;

public class ToolService {
    private final MontoyaApi api;

    public ToolService(MontoyaApi api) {
        this.api = api;
    }

    public void sendToSpider(URL url) {
        HttpRequest request = HttpRequest.httpRequestFromUrl(url.toString());
        api.http().sendRequest(request);
    }

    public void sendToIntruder(String host, int port, boolean useHttps, byte[] request) {
        HttpService httpService = HttpService.httpService(host, port, useHttps);
        ByteArray requestBytes = ByteArray.byteArray(request);
        HttpRequest httpRequest = HttpRequest.httpRequest(httpService, requestBytes);
        api.intruder().sendToIntruder(httpRequest);
    }

    public void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabName) {
        HttpService httpService = HttpService.httpService(host, port, useHttps);
        ByteArray requestBytes = ByteArray.byteArray(request);
        HttpRequest httpRequest = HttpRequest.httpRequest(httpService, requestBytes);
        api.repeater().sendToRepeater(httpRequest, tabName);
    }
}
