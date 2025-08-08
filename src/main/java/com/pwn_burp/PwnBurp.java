package com.pwn_burp;

import burp.*;
import burp.api.montoya.*;
import burp.api.montoya.core.*;
import com.pwn_burp.api.RestServer;
import com.pwn_burp.burp.PwnService;
import com.pwn_burp.config.ConfigManager;

public class PwnBurp implements BurpExtension, IBurpExtender {
    private static volatile MontoyaApi api;
    private static volatile IBurpExtenderCallbacks callbacks;
    private static volatile PwnService pwnService;
    private static volatile ConfigManager config;
    private static volatile RestServer server;
    private static final Object lock = new Object();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        synchronized (lock) {
            PwnBurp.callbacks = callbacks;
            callbacks.setExtensionName("Pwn Burp Extension");
            initializeServices();
        }
    }

    @Override
    public void initialize(MontoyaApi api) {
        synchronized (lock) {
            PwnBurp.api = api;
            // String api_version = api.core().version().toString();
            //api.extension().setName("PWN Burp REST API: " + api_version);
            api.extension().setName("PWN Burp REST API");
            initializeServices();
        }
    }

    private static void initializeServices() {
        if (api != null && callbacks != null && pwnService == null) {
            config = new ConfigManager(api.logging());
            config.loadConfig();
            pwnService = new PwnService(api, callbacks);
            server = new RestServer(config, pwnService);
            server.start();
            api.logging().logToOutput("Burp Suite Extension Initialized: pwn-burp.jar");
        }
    }
}
