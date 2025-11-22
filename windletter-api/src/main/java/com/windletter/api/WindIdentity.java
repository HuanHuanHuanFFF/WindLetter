package com.windletter.api;

import com.windletter.crypto.keys.EccKeyPair;
import com.windletter.crypto.keys.PqcKemKeyPair;

/**
 * Holds signing and KEM key material for one identity.
 * 保存单个身份的签名与 KEM 密钥材料。
 */
public class WindIdentity {
    private String windId;
    private EccKeyPair signKey;
    private EccKeyPair kemEccKey;
    private PqcKemKeyPair kemPqcKey;

    public WindIdentity() {
    }

    public WindIdentity(String windId, EccKeyPair signKey, EccKeyPair kemEccKey, PqcKemKeyPair kemPqcKey) {
        this.windId = windId;
        this.signKey = signKey;
        this.kemEccKey = kemEccKey;
        this.kemPqcKey = kemPqcKey;
    }

    public String getWindId() {
        return windId;
    }

    public void setWindId(String windId) {
        this.windId = windId;
    }

    public EccKeyPair getSignKey() {
        return signKey;
    }

    public void setSignKey(EccKeyPair signKey) {
        this.signKey = signKey;
    }

    public EccKeyPair getKemEccKey() {
        return kemEccKey;
    }

    public void setKemEccKey(EccKeyPair kemEccKey) {
        this.kemEccKey = kemEccKey;
    }

    public PqcKemKeyPair getKemPqcKey() {
        return kemPqcKey;
    }

    public void setKemPqcKey(PqcKemKeyPair kemPqcKey) {
        this.kemPqcKey = kemPqcKey;
    }
}
