package org.bouncycastle.learning;

import java.security.Security;
import java.util.Enumeration;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/**
 * Learning test — demonstrates the Bouncy Castle module ecosystem.
 */
@Slf4j
public class ModuleOverviewTest
{
    @Test
    public void showModuleOverview()
        throws Exception
    {
        log.info("=== Bouncy Castle Module Overview ===");

        // --- prov: JCE provider, registers BC algorithms into java.security ---
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        log.info("[prov]  bcprov — JCE provider with {} security entries",
            Security.getProvider("BC").size());
        log.info("        Sample algorithms:");
        Enumeration<Object> keys = Security.getProvider("BC").keys();
        int shown = 0;
        while (keys.hasMoreElements() && shown < 8)
        {
            log.info("          {}", keys.nextElement());
            shown++;
        }

        log.info("");
        log.info("=== Module Summary ===");
        log.info("[core]  bccore  — low-level crypto: ASN.1, encoders, ciphers, digests");
        log.info("[util]  bcutil  — utilities: PEM parsing, code generation, test helpers");
        log.info("[prov]  bcprov  — JCE provider implementation (registered above)");
        log.info("[pkix]  bcpkix  — PKIX/CMS: X.509 certs, CRMF, CMP, TSP, signed data");
        log.info("[pg]    bcpg    — OpenPGP: key generation, encryption, signatures (RFC 4880)");
        log.info("[tls]   bctls   — TLS 1.2/1.3 protocol implementation");
        log.info("[mls]   bcmls   — Messaging Layer Security (RFC 9420)");
        log.info("[mail]  bcmail  — S/MIME email signing/encryption (javax.mail)");
        log.info("[jmail] bcjmail — S/MIME email signing/encryption (jakarta.mail)");
    }
}
