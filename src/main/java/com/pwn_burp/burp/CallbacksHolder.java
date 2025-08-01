package com.pwn_burp.burp;

import burp.IBurpExtenderCallbacks;

public class CallbacksHolder {
    private static IBurpExtenderCallbacks callbacks;

    public static void setCallbacks(IBurpExtenderCallbacks callbacks) {
        if (callbacks == null) {
            throw new IllegalArgumentException("IBurpExtenderCallbacks cannot be null");
        }
        CallbacksHolder.callbacks = callbacks;
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        if (callbacks == null) {
            throw new IllegalStateException("Callbacks not initialized. Ensure setCallbacks is called in registerExtenderCallbacks.");
        }
        return callbacks;
    }
}
