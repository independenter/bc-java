package org.bouncycastle.learning.asymmetric.rsa;

public class RSA2048Sha256OaepTest
    extends AbstractRSATest
{
    @Override
    protected int getKeySize()
    {
        return 2048;
    }

    @Override
    protected String getSignatureAlgorithm()
    {
        return "SHA256withRSA";
    }

    @Override
    protected String getCipherAlgorithm()
    {
        return "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    }
}
