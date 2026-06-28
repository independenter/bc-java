package org.bouncycastle.learning.asymmetric.sm2;

public class SM2CipherSignatureTest
    extends AbstractSM2Test
{
    @Override
    protected String getSignatureAlgorithm()
    {
        return "SM3withSM2";
    }

    @Override
    protected String getCipherAlgorithm()
    {
        return "SM2";
    }
}
