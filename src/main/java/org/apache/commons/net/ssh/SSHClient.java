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

package org.apache.commons.net.ssh;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.net.SocketClient;
import org.apache.commons.net.ssh.cipher.AES128CBC;
import org.apache.commons.net.ssh.cipher.AES192CBC;
import org.apache.commons.net.ssh.cipher.AES256CBC;
import org.apache.commons.net.ssh.cipher.BlowfishCBC;
import org.apache.commons.net.ssh.cipher.TripleDESCBC;
import org.apache.commons.net.ssh.compression.CompressionNone;
import org.apache.commons.net.ssh.kex.DHG1;
import org.apache.commons.net.ssh.kex.DHG14;
import org.apache.commons.net.ssh.mac.HMACMD5;
import org.apache.commons.net.ssh.mac.HMACMD596;
import org.apache.commons.net.ssh.mac.HMACSHA1;
import org.apache.commons.net.ssh.mac.HMACSHA196;
import org.apache.commons.net.ssh.random.BouncyCastleRandom;
import org.apache.commons.net.ssh.random.JCERandom;
import org.apache.commons.net.ssh.random.SingletonRandomFactory;
import org.apache.commons.net.ssh.signature.SignatureDSA;
import org.apache.commons.net.ssh.signature.SignatureRSA;
import org.apache.commons.net.ssh.util.SecurityUtils;
import org.apache.log4j.BasicConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSHClient extends SocketClient
{
    /** Default SSH port */
    public static final int DEFAULT_PORT = 22;
    
    public static void main(String[] args) throws Exception
    {
        BasicConfigurator.configure(); // logging
        SSHClient s = new SSHClient();
        s.connect("localhost", 22);
        s.disconnect();
    }
    
    protected static FactoryManager makeDefaultFactoryManager()
    {
        FactoryManager fm = new FactoryManager();
        // DHG14 uses 2048 bits key which are not supported by the default JCE
        // provider
        if (SecurityUtils.isBouncyCastleRegistered())
        {
            fm.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>> asList(new DHG14.Factory(),
                                                                                 new DHG1.Factory()));
            fm.setRandomFactory(new SingletonRandomFactory(new BouncyCastleRandom.Factory()));
        } else
        {
            fm.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>> asList(new DHG1.Factory()));
            fm.setRandomFactory(new SingletonRandomFactory(new JCERandom.Factory()));
        }
        List<NamedFactory<Cipher>> avail = new LinkedList<NamedFactory<Cipher>>();
        avail.add(new AES128CBC.Factory());
        avail.add(new TripleDESCBC.Factory());
        avail.add(new BlowfishCBC.Factory());
        avail.add(new AES192CBC.Factory());
        avail.add(new AES256CBC.Factory());
        
        for (Iterator<NamedFactory<Cipher>> i = avail.iterator(); i.hasNext();)
        {
            final NamedFactory<Cipher> f = i.next();
            try
            {
                final Cipher c = f.create();
                final byte[] key = new byte[c.getBlockSize()];
                final byte[] iv = new byte[c.getIVSize()];
                c.init(Cipher.Mode.Encrypt, key, iv);
            } catch (InvalidKeyException e)
            {
                i.remove();
            } catch (Exception e)
            {
                i.remove();
            }
        }
        fm.setCipherFactories(avail);
        
        fm.setCompressionFactories(Arrays.<NamedFactory<Compression>> asList(new CompressionNone.Factory()));
        fm.setMACFactories(Arrays.<NamedFactory<MAC>> asList(new HMACMD5.Factory(), new HMACSHA1.Factory(),
                                                             new HMACMD596.Factory(), new HMACSHA196.Factory()));
        fm.setSignatureFactories(Arrays.<NamedFactory<Signature>> asList(new SignatureDSA.Factory(),
                                                                         new SignatureRSA.Factory()));
        
        return fm;
    }
    
    /** logger */
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    private Session session;
    
    SSHClient()
    {
    }
    
    @Override
    public void disconnect() throws IOException
    {
        if (session.isRunning())
            session.disconnect(SSHConstants.SSH_DISCONNECT_BY_APPLICATION, "Session closed by user");
        super.disconnect();
    }
    
    public boolean isAuthenticated()
    {
        return session.isAuthenticated();
    }
    
    @Override
    protected void _connectAction_() throws IOException
    {
        super._connectAction_();
        session = new Session(SSHClient.makeDefaultFactoryManager(),
                              _input_, _output_);
        try
        {
            session.init();
        } catch (Exception e)
        {
            throw new IOException(e);
        }
    }
    
}
