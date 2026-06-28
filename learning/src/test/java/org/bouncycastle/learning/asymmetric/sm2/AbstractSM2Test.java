package org.bouncycastle.learning.asymmetric.sm2;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import javax.crypto.Cipher;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

/**
 * Abstract base for SM2 signature/encryption learning tests.
 * SM2 is a Chinese national elliptic-curve algorithm; the JCE name is "SM2".
 */
@Slf4j
public abstract class AbstractSM2Test
{
    protected abstract String getSignatureAlgorithm();
    protected abstract String getCipherAlgorithm();

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
        byte[] message = "Hello SM2!".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "BC");
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(getSignatureAlgorithm(), "BC");
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(getSignatureAlgorithm(), "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(message);
        org.junit.Assert.assertTrue(
            "SM2 verification failed for " + getSignatureAlgorithm(),
            verifier.verify(signature));

        log.info("[SM2] {} signature length: {}", getSignatureAlgorithm(), signature.length);
    }

    @Test
    public void testEncryptDecrypt()
        throws Exception
    {
        byte[] plaintext = "SM2 plaintext".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "BC");
        KeyPair kp = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance(getCipherAlgorithm(), "BC");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] ciphertext = cipher.doFinal(plaintext);

        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decrypted = cipher.doFinal(ciphertext);

        org.junit.Assert.assertArrayEquals(
            "SM2 " + getCipherAlgorithm() + " round-trip failed",
            plaintext, decrypted);

        log.info("[SM2] {} ciphertext length: {}", getCipherAlgorithm(), ciphertext.length);
    }

    @Test
    public void testKeyParsing()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "BC");
        KeyPair kp = kpg.generateKeyPair();

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        ASN1OctetString seq = (ASN1OctetString) privInfo.getPrivateKey();
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        log.info("[SM2] private key encoding length: {}", seq.getOctets().length);
        log.info("[SM2] public key encoding length: {}", pubInfo.getEncoded().length);

        org.junit.Assert.assertTrue(
            "SM2 public key should not be empty",
            pubInfo.getEncoded().length > 0);
    }
}
