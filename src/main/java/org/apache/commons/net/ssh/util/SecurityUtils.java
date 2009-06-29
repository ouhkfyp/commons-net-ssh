/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.commons.net.ssh.util;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class SecurityUtils
{
    
    private static class BouncyCastleRegistration
    {
        public void run() throws Exception
        {
            if (java.security.Security.getProvider(BOUNCY_CASTLE) == null) {
                LOG.info("Trying to register BouncyCastle as a JCE provider");
                java.security.Security.addProvider(new BouncyCastleProvider());
                MessageDigest.getInstance("MD5", BOUNCY_CASTLE);
                KeyAgreement.getInstance("DH", BOUNCY_CASTLE);
                LOG.info("Registration succeeded");
            } else
                LOG.info("BouncyCastle already registered as a JCE provider");
            securityProvider = BOUNCY_CASTLE;
        }
    }
    
    public static final String BOUNCY_CASTLE = "BC";
    
    private static final Logger LOG = LoggerFactory.getLogger(SecurityUtils.class);
    private static String securityProvider = null;
    private static Boolean registerBouncyCastle;
    
    private static boolean registrationDone;
    
    public static synchronized Cipher getCipher(String transformation)
            throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException
    {
        register();
        if (getSecurityProvider() == null)
            return Cipher.getInstance(transformation);
        else
            return Cipher.getInstance(transformation, getSecurityProvider());
    }
    
    /**
     * Computes the fingerprint for a public key, in the standard SSH format, e.g.
     * "4b:69:6c:72:6f:79:20:77:61:73:20:68:65:72:65:21"
     * 
     * @param key
     *            the public key
     * @return the fingerprint
     * @see <a href="http://tools.ietf.org/html/draft-friedl-secsh-fingerprint-00">specification</a>
     */
    public static String getFingerprint(PublicKey key)
    {
        MessageDigest md5 = null;
        try {
            md5 = getMessageDigest("MD5");
        } catch (NoSuchAlgorithmException e) { // can't happen.
            e.printStackTrace();
        } catch (NoSuchProviderException e) { // can't happen.
            e.printStackTrace();
        }
        Buffer buf = new Buffer();
        switch (Constants.KeyType.fromKey(key))
        {
        case RSA:
            RSAPublicKey rsa = (RSAPublicKey) key;
            buf.putString(Constants.KeyType.RSA.toString());
            buf.putMPInt(rsa.getPublicExponent());
            buf.putMPInt(rsa.getModulus());
            break;
        case DSA:
            buf.putString(Constants.KeyType.DSA.toString());
            DSAPublicKey dsa = (DSAPublicKey) key;
            DSAParams params = dsa.getParams();
            buf.putMPInt(params.getP());
            buf.putMPInt(params.getQ());
            buf.putMPInt(params.getG());
            buf.putMPInt(dsa.getY());
            break;
        default:
            assert false;
        }
        md5.update(buf.array(), 0, buf.available());
        String undelimed = BufferUtils.toHex(md5.digest());
        String fp = undelimed.substring(0, 2);
        for (int i = 2; i <= undelimed.length() - 2; i += 2)
            fp += ":" + undelimed.substring(i, i + 2);
        return fp;
    }
    
    public static synchronized KeyAgreement getKeyAgreement(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException
    {
        register();
        if (getSecurityProvider() == null)
            return KeyAgreement.getInstance(algorithm);
        else
            return KeyAgreement.getInstance(algorithm, getSecurityProvider());
    }
    
    public static synchronized KeyFactory getKeyFactory(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException
    {
        register();
        if (getSecurityProvider() == null)
            return KeyFactory.getInstance(algorithm);
        else
            return KeyFactory.getInstance(algorithm, getSecurityProvider());
    }
    
    public static synchronized KeyPairGenerator getKeyPairGenerator(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException
    {
        register();
        if (getSecurityProvider() == null)
            return KeyPairGenerator.getInstance(algorithm);
        else
            return KeyPairGenerator.getInstance(algorithm, getSecurityProvider());
    }
    
    public static synchronized Mac getMAC(String algorithm) throws NoSuchAlgorithmException,
            NoSuchProviderException
    {
        register();
        if (getSecurityProvider() == null)
            return Mac.getInstance(algorithm);
        else
            return Mac.getInstance(algorithm, getSecurityProvider());
    }
    
    public static synchronized MessageDigest getMessageDigest(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException
    {
        register();
        if (getSecurityProvider() == null)
            return MessageDigest.getInstance(algorithm);
        else
            return MessageDigest.getInstance(algorithm, getSecurityProvider());
    }
    
    public static synchronized String getSecurityProvider()
    {
        register();
        return securityProvider;
    }
    
    public static synchronized Signature getSignature(String algorithm)
            throws NoSuchAlgorithmException, NoSuchProviderException
    {
        register();
        if (getSecurityProvider() == null)
            return Signature.getInstance(algorithm);
        else
            return Signature.getInstance(algorithm, getSecurityProvider());
    }
    
    public static synchronized boolean isBouncyCastleRegistered()
    {
        register();
        return BOUNCY_CASTLE.equals(securityProvider);
    }
    
    private static void register()
    {
        if (!registrationDone) {
            if (securityProvider == null && (registerBouncyCastle == null || registerBouncyCastle))
                // Use an inner class to avoid a strong dependency on BouncyCastle
                try {
                    new BouncyCastleRegistration().run();
                } catch (Throwable t) {
                    if (registerBouncyCastle == null)
                        LOG.info("BouncyCastle not registered, using the default JCE provider");
                    else {
                        LOG.error("Failed to register BouncyCastle as the defaut JCE provider");
                        throw new RuntimeException(
                                "Failed to register BouncyCastle as the defaut JCE provider", t);
                    }
                }
            registrationDone = true;
        }
    }
    
    public static synchronized void setRegisterBouncyCastle(boolean registerBouncyCastle)
    {
        SecurityUtils.registerBouncyCastle = registerBouncyCastle;
        registrationDone = false;
    }
    
    public static synchronized void setSecurityProvider(String securityProvider)
    {
        SecurityUtils.securityProvider = securityProvider;
        registrationDone = false;
    }
    
}
