package com.pwn_burp.api.models;

import com.google.gson.annotations.SerializedName;

public class ScanIssue {
    @SerializedName("name")
    public String name;
    @SerializedName("severity")
    public String severity;
    @SerializedName("url")
    public String url;
    // Add other fields as needed
}
