# windletter-api

Application-facing facade and contracts (v1.0 API shell):

- `com.windletter.api`
  - `WindLetterSender`
  - `WindLetterReceiver`
- `com.windletter.api.enums`
  - `WindMode`, `KeyAlgProfile`, `SigningOption`
  - `DecryptStatus`, `VerificationStatus`, `VerificationPolicy`
- `com.windletter.api.model`
  - request/result DTO records
  - identity reference records
- `com.windletter.api.spi`
  - `RecipientKeyStore`
  - `IdentityService`
  - key material records

Notes:

- This module currently provides contracts only.
- No protocol/crypto implementation is included at this stage.
