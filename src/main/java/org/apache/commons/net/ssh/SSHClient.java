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
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.net.SocketClient;
import org.apache.commons.net.ssh.cipher.AES128CBC;
import org.apache.commons.net.ssh.cipher.AES192CBC;
import org.apache.commons.net.ssh.cipher.AES256CBC;
import org.apache.commons.net.ssh.cipher.BlowfishCBC;
import org.apache.commons.net.ssh.cipher.Cipher;
import org.apache.commons.net.ssh.cipher.TripleDESCBC;
import org.apache.commons.net.ssh.compression.Compression;
import org.apache.commons.net.ssh.compression.CompressionDelayedZlib;
import org.apache.commons.net.ssh.compression.CompressionNone;
import org.apache.commons.net.ssh.compression.CompressionZlib;
import org.apache.commons.net.ssh.connection.Connection;
import org.apache.commons.net.ssh.kex.DHG1;
import org.apache.commons.net.ssh.kex.DHG14;
import org.apache.commons.net.ssh.kex.KeyExchange;
import org.apache.commons.net.ssh.mac.HMACMD5;
import org.apache.commons.net.ssh.mac.HMACMD596;
import org.apache.commons.net.ssh.mac.HMACSHA1;
import org.apache.commons.net.ssh.mac.HMACSHA196;
import org.apache.commons.net.ssh.mac.MAC;
import org.apache.commons.net.ssh.random.BouncyCastleRandom;
import org.apache.commons.net.ssh.random.JCERandom;
import org.apache.commons.net.ssh.random.SingletonRandomFactory;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.signature.SignatureDSA;
import org.apache.commons.net.ssh.signature.SignatureRSA;
import org.apache.commons.net.ssh.transport.Transport;
import org.apache.commons.net.ssh.userauth.UserAuth;
import org.apache.commons.net.ssh.util.SecurityUtils;
import org.apache.log4j.BasicConfigurator;

public class SSHClient extends SocketClient
{
    
    protected static FactoryManager getDefaultFactoryManager()
    {
        FactoryManager fm = new FactoryManager();
        
        // DHG14 uses 2048 bits key which are not supported by the default JCE provider
        if (SecurityUtils.isBouncyCastleRegistered()) {
            fm.setKeyExchangeFactories(new LinkedList<NamedFactory<KeyExchange>>()
            {
                {
                    add(new DHG14.Factory());
                    add(new DHG1.Factory());
                }
            });
            fm.setRandomFactory(new SingletonRandomFactory(new BouncyCastleRandom.Factory()));
        } else {
            fm.setKeyExchangeFactories(new LinkedList<NamedFactory<KeyExchange>>()
            {
                {
                    add(new DHG1.Factory());
                }
            });
            fm.setRandomFactory(new SingletonRandomFactory(new JCERandom.Factory()));
        }
        
        List<NamedFactory<Cipher>> avail = new LinkedList<NamedFactory<Cipher>>()
        {
            {
                add(new AES256CBC.Factory());
                add(new AES192CBC.Factory());
                add(new AES128CBC.Factory());
                add(new BlowfishCBC.Factory());
                add(new TripleDESCBC.Factory());
            }
        };
        for (Iterator<NamedFactory<Cipher>> i = avail.iterator(); i.hasNext();) {
            final NamedFactory<Cipher> f = i.next();
            try {
                final Cipher c = f.create();
                final byte[] key = new byte[c.getBlockSize()];
                final byte[] iv = new byte[c.getIVSize()];
                c.init(Cipher.Mode.Encrypt, key, iv);
            } catch (InvalidKeyException e) {
                i.remove();
            } catch (Exception e) {
                i.remove();
            }
        }
        fm.setCipherFactories(avail);
        
        fm.setCompressionFactories(new LinkedList<NamedFactory<Compression>>()
        {
            {
                add(new CompressionZlib.Factory());
                add(new CompressionDelayedZlib.Factory());
                add(new CompressionNone.Factory());
            }
        });
        
        fm.setMACFactories(new LinkedList<NamedFactory<MAC>>()
        {
            {
                add(new HMACSHA1.Factory());
                add(new HMACSHA196.Factory());
                add(new HMACMD5.Factory());
                add(new HMACMD596.Factory());
            }
        });
        
        fm.setSignatureFactories(new LinkedList<NamedFactory<Signature>>()
        {
            {
                add(new SignatureDSA.Factory());
                add(new SignatureRSA.Factory());
            }
        });
        
        return fm;
    }
    
    public static void main(String[] args) throws Exception
    {
        BasicConfigurator.configure(); // logging
        SSHClient s = new SSHClient();
        
        // still working on support for reading in known_hosts...
        s.setHostKeyVerifier(new HostKeyVerifier()
        {
            public boolean verify(InetAddress address, PublicKey key)
            {
                return "localhost".equals(address.getHostName())
                        && "2e:26:99:ec:71:51:ca:a0:b3:1d:3d:10:4c:a7:80:e5".equals(SecurityUtils
                                .getFingerprint(key));
            }
        });
        
        s.connect("localhost");
        s.disconnect();
    }
    
    private final Session trans;
    private final UserAuth auth;
    private final Connection conn;
    
    private HostKeyVerifier hostKeyVerifier;
    
    public SSHClient()
    {
        this(SSHClient.getDefaultFactoryManager());
    }
    
    public SSHClient(FactoryManager fm)
    {
        trans = new Transport(fm);
        conn = new Connection(trans);
        auth = new UserAuth(trans, conn.getName());
        setDefaultPort(Constants.DEFAULT_PORT);
    }
    
    @Override
    protected void _connectAction_() throws IOException
    {
        super._connectAction_();
        try {
            trans.setHostKeyVerifier(hostKeyVerifier);
            trans.init(_socket_);
            trans.startService(auth);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
    
    public void authPassword(String username, char[] password)
    {
        auth.authPassword(username, password);
    }
    
    @Override
    public void disconnect() throws IOException
    {
        trans.disconnect(Constants.SSH_DISCONNECT_BY_APPLICATION, "Session closed by user");
        super.disconnect();
    }
    
    public void setHostKeyVerifier(HostKeyVerifier hostKeyVerifier)
    {
        this.hostKeyVerifier = hostKeyVerifier;
    }
}
