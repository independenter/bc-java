package org.bouncycastle.learning.pqc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;

/**
 * Abstract base for ML-DSA-WITH-SHA512 learning tests.
 * Subclasses provide the concrete parameter set and algorithm name.
 */
@Slf4j
public abstract class AbstractMLDSATest
{
    protected abstract String getAlgorithmName();
    protected abstract MLDSAParameterSpec getParameterSpec();

    @Before
    public void setUp()
    {
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    public void testSignAndVerify()
        throws Exception
    {
        byte[] msg = "Hello World!".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(getParameterSpec());
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance(getAlgorithmName(), "BC");
        sig.initSign(kp.getPrivate());
        sig.update(msg);
        byte[] signature = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(msg);
        org.junit.Assert.assertTrue(
            "signature verification failed for " + getAlgorithmName(),
            sig.verify(signature));
    }

    @Test
    public void testAsn1KeyParsing()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        kpg.initialize(getParameterSpec());
        KeyPair kp = kpg.generateKeyPair();

        byte[] seed = parsePrivateKeySeed(kp);
        byte[] expanded = parseExpandedPrivateKey(kp);
        byte[] pubBytes = parsePublicKeyBytes(kp);

        log.info("[{}] private key seed length: {}", getAlgorithmName(), seed.length);
        log.info("[{}] expanded private key length: {}", getAlgorithmName(), expanded.length);
        log.info("[{}] public key bytes length: {}", getAlgorithmName(), pubBytes.length);

        org.junit.Assert.assertTrue("seed should be 32 bytes", seed.length == 32);
        org.junit.Assert.assertTrue("public key must not be empty", pubBytes.length > 0);
    }

    /**
     * ASN.1 parse the seed from an ML-DSA private key (expanded form).
     */
    protected byte[] parsePrivateKeySeed(KeyPair kp)
        throws Exception
    {
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        ASN1OctetString seq = privInfo.getPrivateKey();
        ASN1Sequence s = ASN1Sequence.getInstance(seq.getOctets());
        return ASN1OctetString.getInstance(s.getObjectAt(0)).getOctets();
    }

    /**
     * ASN.1 parse the expanded private key data.
     */
    protected byte[] parseExpandedPrivateKey(KeyPair kp)
        throws Exception
    {
        MLDSAPrivateKey privKey = (MLDSAPrivateKey)kp.getPrivate();
        return privKey.getPrivateData();
    }

    /**
     * ASN.1 parse the raw public key bytes.
     */
    protected byte[] parsePublicKeyBytes(KeyPair kp)
        throws Exception
    {
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        return pubInfo.getPublicKeyData().getOctets();
    }
}
