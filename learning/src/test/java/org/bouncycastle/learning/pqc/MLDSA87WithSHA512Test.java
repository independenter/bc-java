package org.bouncycastle.learning.pqc;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

public class MLDSA87WithSHA512Test
    extends AbstractMLDSATest
{
    @Override
    protected String getAlgorithmName()
    {
        return "ML-DSA-87-WITH-SHA512";
    }

    @Override
    protected MLDSAParameterSpec getParameterSpec()
    {
        return MLDSAParameterSpec.ml_dsa_87_with_sha512;
    }
}
