package org.bouncycastle.learning;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Utility class for JCE crypto operations and provider introspection.
 */
public final class CryptoHelper
{
    private CryptoHelper()
    {
    }

    /**
     * List all algorithms registered by a provider.
     *
     * @param providerName the name of the provider (e.g., "SM9")
     * @param filter       optional prefix filter (e.g., "Cipher.", "Signature."); null means no filter
     * @return list of algorithm names matching the filter
     */
    public static List<String> listAlgorithms(String providerName, String filter)
    {
        Provider provider = Security.getProvider(providerName);
        if (provider == null)
        {
            return Collections.emptyList();
        }

        List<String> algorithms = new ArrayList<>();
        for (Object key : provider.keySet())
        {
            String name = (String)key;
            if (filter == null || name.startsWith(filter))
            {
                algorithms.add(name);
            }
        }
        Collections.sort(algorithms);
        return algorithms;
    }

    /**
     * List all algorithms from all registered providers.
     *
     * @param filter optional prefix filter; null means no filter
     * @return list of all algorithm names matching the filter
     */
    public static List<String> listAllAlgorithms(String filter)
    {
        List<String> algorithms = new ArrayList<>();
        for (Provider provider : Security.getProviders())
        {
            for (Object key : provider.keySet())
            {
                String name = (String)key;
                if (filter == null || name.startsWith(filter))
                {
                    if (!algorithms.contains(name))
                    {
                        algorithms.add(name);
                    }
                }
            }
        }
        Collections.sort(algorithms);
        return algorithms;
    }
}
