Gradle driving keytool to create keystores.

There are two sets of keys generated here.

OIDC - used for the signing and verification of signature of oidc requests.
SSL - used for the ssl, and trusting of ssl certs

The OP has an SSL key, and an OIDC key. It trusts no-one.

The RP has an SSL key, and trusts the OIDC key, and trusts the ssl key of the RS, and the OP

The RS has an SSL key, and (may) trust the OIDC key, and trusts the ssl key of the RS and the OP


Signed JWT will also require a keystore/truststore used only by the Apps.
This isn't present yet.
