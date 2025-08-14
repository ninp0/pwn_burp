package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import java.net.URL;

public class ShutdownService {
    private final MontoyaApi api;

    public ShutdownService(MontoyaApi api) {
        this.api = api;
    }

    public void shutdown() {
        api.burpSuite().shutdown();
    }
}
