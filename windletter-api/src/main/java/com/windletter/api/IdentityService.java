package com.windletter.api;

/**
 * Application-facing storage for identities.
 * 面向应用的身份存取接口。
 */
public interface IdentityService {
    WindIdentity generateIdentity();

    void storeIdentity(WindIdentity identity);

    WindIdentity loadIdentity(String windId);
}
