package org.bouncycastle.learning.pqc;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

public class MLDSA65WithSHA512Test
    extends AbstractMLDSATest
{
    @Override
    protected String getAlgorithmName()
    {
        return "ML-DSA-65-WITH-SHA512";
    }

    @Override
    protected MLDSAParameterSpec getParameterSpec()
    {
        return MLDSAParameterSpec.ml_dsa_65_with_sha512;
    }
}
