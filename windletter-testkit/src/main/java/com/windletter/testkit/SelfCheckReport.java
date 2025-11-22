package com.windletter.testkit;

/**
 * Result container for self-check diagnostics.
 * 自检诊断结果的承载结构。
 */
public class SelfCheckReport {
    private boolean allPassed;
    private String details;

    public SelfCheckReport() {
    }

    public SelfCheckReport(boolean allPassed, String details) {
        this.allPassed = allPassed;
        this.details = details;
    }

    public boolean isAllPassed() {
        return allPassed;
    }

    public void setAllPassed(boolean allPassed) {
        this.allPassed = allPassed;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }
}
