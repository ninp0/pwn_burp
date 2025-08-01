package com.pwn_burp.config;

import burp.api.montoya.logging.Logging;
import java.io.IOException;
import java.util.Properties;

public class ConfigManager {
    private final Logging logging;
    private String serverAddress = "127.0.0.1";
    private int serverPort = 1337;

    public ConfigManager(Logging logging) {
        this.logging = logging;
        loadConfig();
    }

    public void loadConfig() {
        Properties props = new Properties();
        try {
            props.load(ConfigManager.class.getResourceAsStream("/config.properties"));
            serverAddress = props.getProperty("server.address", serverAddress);
            serverPort = Integer.parseInt(props.getProperty("server.port", String.valueOf(serverPort)));
        } catch (IOException | NumberFormatException e) {
            logging.logToError("Failed to load config: " + e.getMessage());
        }

        // Override with system properties if provided
        serverAddress = System.getProperty("server.address", serverAddress);
        String portStr = System.getProperty("server.port", String.valueOf(serverPort));
        try {
            serverPort = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            logging.logToError("Invalid server.port system property: " + portStr);
        }
    }

    public String getServerAddress() {
        return serverAddress;
    }

    public int getServerPort() {
        return serverPort;
    }
}
