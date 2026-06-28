package org.bouncycastle.learning.asymmetric.rsa;

public class RSA3072Sha512OaepTest
    extends AbstractRSATest
{
    @Override
    protected int getKeySize()
    {
        return 3072;
    }

    @Override
    protected String getSignatureAlgorithm()
    {
        return "SHA512withRSA";
    }

    @Override
    protected String getCipherAlgorithm()
    {
        return "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
    }
}
