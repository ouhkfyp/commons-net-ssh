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

import static org.apache.commons.net.ssh.util.Constants.DEFAULT_PORT;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
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
import org.apache.commons.net.ssh.connection.ConnectionProtocol;
import org.apache.commons.net.ssh.connection.ConnectionService;
import org.apache.commons.net.ssh.kex.DHG1;
import org.apache.commons.net.ssh.kex.DHG14;
import org.apache.commons.net.ssh.kex.KeyExchange;
import org.apache.commons.net.ssh.keyprovider.FileKeyProvider;
import org.apache.commons.net.ssh.keyprovider.OpenSSHKeyFile;
import org.apache.commons.net.ssh.keyprovider.PKCS8KeyFile;
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
import org.apache.commons.net.ssh.userauth.AuthBuilder;
import org.apache.commons.net.ssh.util.KnownHosts;
import org.apache.commons.net.ssh.util.SecurityUtils;

/**
 * TODO javadocs
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class SSHClient extends SocketClient
{
    
    @SuppressWarnings("unchecked")
    protected static FactoryManager getDefaultFactoryManager()
    {
        FactoryManager fm = new FactoryManager();
        
        if (SecurityUtils.isBouncyCastleRegistered()) {
            
            fm.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>> asList(new DHG14.Factory(),
                                                                                 new DHG1.Factory()));
            
            fm.setRandomFactory(new SingletonRandomFactory(new BouncyCastleRandom.Factory()));
            
            fm.setFileKeyProviderFactories(Arrays.<NamedFactory<FileKeyProvider>> asList(new PKCS8KeyFile.Factory(),
                                                                                         new OpenSSHKeyFile.Factory()));
            
        } else {
            
            fm.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>> asList(new DHG1.Factory()));
            
            fm.setRandomFactory(new SingletonRandomFactory(new JCERandom.Factory()));
            
            fm.setFileKeyProviderFactories(Arrays.<NamedFactory<FileKeyProvider>> asList()); // empty
        }
        
        List<NamedFactory<Cipher>> avail =
                new LinkedList<NamedFactory<Cipher>>(Arrays.<NamedFactory<Cipher>> asList(new AES256CBC.Factory(),
                                                                                          new AES192CBC.Factory(),
                                                                                          new AES128CBC.Factory(),
                                                                                          new BlowfishCBC.Factory(),
                                                                                          new TripleDESCBC.Factory()));
        
        for (Iterator<NamedFactory<Cipher>> i = avail.iterator(); i.hasNext();) {
            final NamedFactory<Cipher> f = i.next();
            try {
                final Cipher c = f.create();
                final byte[] key = new byte[c.getBlockSize()];
                final byte[] iv = new byte[c.getIVSize()];
                c.init(Cipher.Mode.Encrypt, key, iv);
            } catch (Exception e) {
                i.remove();
            }
        }
        
        fm.setCipherFactories(avail);
        
        fm.setCompressionFactories(Arrays.<NamedFactory<Compression>> asList(new CompressionNone.Factory(),
                                                                             new CompressionDelayedZlib.Factory(),
                                                                             new CompressionZlib.Factory()));
        
        fm.setMACFactories(Arrays.<NamedFactory<MAC>> asList(new HMACSHA1.Factory(), new HMACSHA196.Factory(),
                                                             new HMACMD5.Factory(), new HMACMD596.Factory()));
        
        fm.setSignatureFactories(Arrays.<NamedFactory<Signature>> asList(new SignatureDSA.Factory(),
                                                                         new SignatureRSA.Factory()));
        
        return fm;
    }
    
    protected final Session trans;
    
    protected final ConnectionService conn;
    
    protected HostKeyVerifier hostKeyVerifier;
    
    public SSHClient()
    {
        this(SSHClient.getDefaultFactoryManager());
    }
    
    public SSHClient(FactoryManager fm)
    {
        setDefaultPort(DEFAULT_PORT);
        trans = new Transport(fm);
        conn = new ConnectionProtocol(trans);
    }
    
    public void addHostKeyVerifier(HostKeyVerifier hostKeyVerifier)
    {
        trans.addHostKeyVerifier(hostKeyVerifier);
    }
    
    @Override
    public void disconnect() throws IOException
    {
        trans.disconnect();
        super.disconnect();
    }
    
    public AuthBuilder getAuthBuilder()
    {
        return new AuthBuilder(trans, conn, System.getProperty("user.name"));
    }
    
    public void initKnownHosts(String... locations) throws IOException
    {
        for (String loc : locations)
            trans.addHostKeyVerifier(new KnownHosts(loc));
    }
    
    public void initUserKnownHosts()
    {
        String kh = System.getProperty("user.home") + File.separator + ".ssh" + File.separator + "known_hosts";
        try {
            initKnownHosts(kh, // "~/.ssh/known_hosts" 
                           kh + "2"); // "~/.ssh/known_hosts2"
        } catch (IOException ignored) {
            
        }
    }
    
    @Override
    public boolean isConnected()
    {
        return super.isConnected() && trans.isRunning();
    }
    
    public FileKeyProvider loadKeyFile(String location) throws IOException
    {
        return loadKeyFile(location, "");
    }
    
    public FileKeyProvider loadKeyFile(String location, PasswordFinder pwdf) throws IOException
    {
        String format = SecurityUtils.detectKeyFileFormat(location);
        if (format.equals("unknown"))
            throw new IOException("Unknown key file format");
        FileKeyProvider fkp =
                NamedFactory.Utils.create(trans.getFactoryManager().getFileKeyProviderFactories(), format);
        fkp.init(location, pwdf);
        return fkp;
    }
    
    public FileKeyProvider loadKeyFile(String location, String passphrase) throws IOException
    {
        return loadKeyFile(location, PasswordFinder.Util.createOneOff(passphrase));
    }
    
    @Override
    protected void _connectAction_() throws IOException
    {
        super._connectAction_();
        trans.init(_socket_);
    }
    
}
