package org.bouncycastle.learning;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Utility methods for Bouncy Castle learning tests — Java implementation.
 * Demonstrates a Java main source set consumed by both Java and Groovy tests.
 */
public class CryptoHelper
{
    public static byte[] sha256(byte[] input)
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input);
    }

    public static byte[] sha512(byte[] input)
        throws Exception
    {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        return md.digest(input);
    }

    public static List<String> listAlgorithms(String providerName, String filter)
    {
        List<String> result = new ArrayList<String>();
        Provider provider = Security.getProvider(providerName);
        if (provider == null)
        {
            return result;
        }
        Enumeration<Object> keys = provider.keys();
        while (keys.hasMoreElements())
        {
            String key = keys.nextElement().toString();
            if (filter == null || key.contains(filter))
            {
                result.add(key);
            }
        }
        return result;
    }
}
