package org.bouncycastle.learning.asymmetric.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import javax.crypto.Cipher;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

/**
 * Abstract base for RSA signature/encryption learning tests.
 * Subclasses provide the key size, signature algorithm, and cipher algorithm.
 */
@Slf4j
public abstract class AbstractRSATest
{
    protected abstract int getKeySize();
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
        byte[] message = "Hello RSA!".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(getKeySize());
        KeyPair kp = kpg.generateKeyPair();

        Signature signer = Signature.getInstance(getSignatureAlgorithm(), "BC");
        signer.initSign(kp.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(getSignatureAlgorithm(), "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(message);
        org.junit.Assert.assertTrue(
            "RSA " + getKeySize() + " verification failed for " + getSignatureAlgorithm(),
            verifier.verify(signature));

        log.info("[RSA-{}] {} signature length: {}",
            getKeySize(), getSignatureAlgorithm(), signature.length);
    }

    @Test
    public void testEncryptDecrypt()
        throws Exception
    {
        byte[] plaintext = "RSA plaintext".getBytes();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(getKeySize());
        KeyPair kp = kpg.generateKeyPair();

        Cipher cipher = Cipher.getInstance(getCipherAlgorithm(), "BC");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] ciphertext = cipher.doFinal(plaintext);

        cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decrypted = cipher.doFinal(ciphertext);

        org.junit.Assert.assertArrayEquals(
            "RSA-" + getKeySize() + " " + getCipherAlgorithm() + " round-trip failed",
            plaintext, decrypted);

        log.info("[RSA-{}] {} ciphertext length: {}",
            getKeySize(), getCipherAlgorithm(), ciphertext.length);
    }

    @Test
    public void testKeyParsing()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(getKeySize());
        KeyPair kp = kpg.generateKeyPair();

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(privInfo.parsePrivateKey());

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        ASN1Sequence pubSeq = ASN1Sequence.getInstance(pubInfo.parsePublicKey());

        log.info("[RSA-{}] private modulus length: {} bits", getKeySize(), rsaPrivateKey.getModulus().bitLength());
        log.info("[RSA-{}] public modulus length: {} bits", getKeySize(),
            ASN1Integer.getInstance(pubSeq.getObjectAt(0)).getValue().bitLength());

        org.junit.Assert.assertEquals(
            "RSA-" + getKeySize() + " private modulus size mismatch",
            getKeySize(), rsaPrivateKey.getModulus().bitLength());
    }
}
