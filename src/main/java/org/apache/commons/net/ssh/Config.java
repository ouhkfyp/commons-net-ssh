package org.apache.commons.net.ssh;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.net.ssh.cipher.AES128CBC;
import org.apache.commons.net.ssh.cipher.AES128CTR;
import org.apache.commons.net.ssh.cipher.AES192CBC;
import org.apache.commons.net.ssh.cipher.AES192CTR;
import org.apache.commons.net.ssh.cipher.AES256CBC;
import org.apache.commons.net.ssh.cipher.AES256CTR;
import org.apache.commons.net.ssh.cipher.BlowfishCBC;
import org.apache.commons.net.ssh.cipher.Cipher;
import org.apache.commons.net.ssh.cipher.TripleDESCBC;
import org.apache.commons.net.ssh.compression.Compression;
import org.apache.commons.net.ssh.compression.CompressionDelayedZlib;
import org.apache.commons.net.ssh.compression.CompressionNone;
import org.apache.commons.net.ssh.compression.CompressionZlib;
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
import org.apache.commons.net.ssh.random.Random;
import org.apache.commons.net.ssh.random.SingletonRandomFactory;
import org.apache.commons.net.ssh.signature.Signature;
import org.apache.commons.net.ssh.signature.SignatureDSA;
import org.apache.commons.net.ssh.signature.SignatureRSA;
import org.apache.commons.net.ssh.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Container class for {@link NamedFactory} implementations of {@link KeyExchange}, {@link Cipher},
 * {@link Compression}, {@link MAC}, {@link Signature}, {@link Random}, and {@link FileKeyProvider}.
 * <p>
 * This class is used in {@link Transport} initialization.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class Config
{
    
    public static class Builder
    {
        
        String version = "NET_3.0";
        
        private List<NamedFactory<KeyExchange>> keyExchangeFactories;
        private List<NamedFactory<Cipher>> cipherFactories;
        private List<NamedFactory<Compression>> compressionFactories;
        private List<NamedFactory<MAC>> macFactories;
        private List<NamedFactory<Signature>> signatureFactories;
        private List<NamedFactory<FileKeyProvider>> fileKeyProviderFactories;
        private NamedFactory<Random> randomFactory;
        
        @SuppressWarnings("unchecked")
        public Builder()
        {
            if (SecurityUtils.isBouncyCastleRegistered()) {
                keyExchange(new DHG14.Factory(), new DHG1.Factory());
                random(new BouncyCastleRandom.Factory());
                fileKeyProviders(new PKCS8KeyFile.Factory(), new OpenSSHKeyFile.Factory());
            } else {
                keyExchange(new DHG1.Factory());
                random(new JCERandom.Factory());
                fileKeyProviders();
            }
            
            List<NamedFactory<Cipher>> avail = new LinkedList<NamedFactory<Cipher>> //
                    (Arrays.<NamedFactory<Cipher>> asList(new AES128CBC.Factory(), new AES192CTR.Factory(),
                                                          new AES256CTR.Factory(), new AES128CTR.Factory(),
                                                          new AES192CBC.Factory(), new AES256CBC.Factory(),
                                                          new TripleDESCBC.Factory(), new BlowfishCBC.Factory()));
            
            { /*
               * @see https://issues.apache.org/jira/browse/SSHD-24:
               * "AES256 and AES192 requires unlimited cryptography extension"
               */
                for (Iterator<NamedFactory<Cipher>> i = avail.iterator(); i.hasNext();) {
                    final NamedFactory<Cipher> f = i.next();
                    try {
                        final Cipher c = f.create();
                        final byte[] key = new byte[c.getBlockSize()];
                        final byte[] iv = new byte[c.getIVSize()];
                        c.init(Cipher.Mode.Encrypt, key, iv);
                    } catch (Exception e) {
                        log.warn("Disabling cipher: {}", f.getName());
                        i.remove();
                    }
                }
            }
            
            cipher(avail);
            
            compressions(new CompressionNone.Factory(), new CompressionDelayedZlib.Factory(),
                         new CompressionZlib.Factory());
            mac(new HMACSHA1.Factory(), new HMACSHA196.Factory(), new HMACMD5.Factory(), new HMACMD596.Factory());
            signature(new SignatureRSA.Factory(), new SignatureDSA.Factory());
            
        }
        
        public Config build()
        {
            assertNotNull(keyExchangeFactories, cipherFactories, compressionFactories, macFactories,
                          signatureFactories, fileKeyProviderFactories, randomFactory);
            return new Config(this);
        }
        
        public Builder cipher(Collection<NamedFactory<Cipher>> ciphers)
        {
            if (ciphers == null)
                throw new IllegalArgumentException();
            cipherFactories = new LinkedList<NamedFactory<Cipher>>(ciphers);
            return this;
        }
        
        public Builder cipher(NamedFactory<Cipher>... ciphers)
        {
            cipher(Arrays.<NamedFactory<Cipher>> asList(ciphers));
            return this;
        }
        
        public Builder compression(Collection<NamedFactory<Compression>> comps)
        {
            if (comps == null)
                throw new IllegalArgumentException();
            compressionFactories = new LinkedList<NamedFactory<Compression>>(comps);
            return this;
        }
        
        public Builder compressions(NamedFactory<Compression>... comps)
        {
            compression(Arrays.<NamedFactory<Compression>> asList(comps));
            return this;
        }
        
        public Builder fileKeyProviders(Collection<NamedFactory<FileKeyProvider>> fkps)
        {
            if (fkps == null)
                throw new IllegalArgumentException();
            fileKeyProviderFactories = new LinkedList<NamedFactory<FileKeyProvider>>(fkps);
            return this;
        }
        
        public Builder fileKeyProviders(NamedFactory<FileKeyProvider>... fkps)
        {
            fileKeyProviders(Arrays.<NamedFactory<FileKeyProvider>> asList(fkps));
            return this;
        }
        
        public Builder keyExchange(Collection<NamedFactory<KeyExchange>> kexes)
        {
            if (kexes == null)
                throw new IllegalArgumentException();
            keyExchangeFactories = new LinkedList<NamedFactory<KeyExchange>>(kexes);
            return this;
        }
        
        public Builder keyExchange(NamedFactory<KeyExchange>... kexes)
        {
            keyExchange(Arrays.<NamedFactory<KeyExchange>> asList(kexes));
            return this;
        }
        
        public Builder mac(Collection<NamedFactory<MAC>> macs)
        {
            if (macs == null)
                throw new IllegalArgumentException();
            macFactories = new LinkedList<NamedFactory<MAC>>(macs);
            return this;
        }
        
        public Builder mac(NamedFactory<MAC>... macs)
        {
            mac(Arrays.<NamedFactory<MAC>> asList(macs));
            return this;
        }
        
        public Builder random(NamedFactory<Random> random)
        {
            randomFactory = new SingletonRandomFactory(random);
            return this;
        }
        
        public Builder signature(Collection<NamedFactory<Signature>> sigs)
        {
            if (sigs == null)
                throw new IllegalArgumentException();
            signatureFactories = new LinkedList<NamedFactory<Signature>>(sigs);
            return this;
        }
        
        public Builder signature(NamedFactory<Signature>... sigs)
        {
            signature(Arrays.<NamedFactory<Signature>> asList(sigs));
            return this;
        }
        
        public Builder version(String version)
        {
            this.version = version.toUpperCase();
            return this;
        }
        
        private void assertNotNull(Object... objects)
        {
            for (Object o : objects)
                if (o == null)
                    throw new AssertionError("null values");
        }
        
    }
    
    protected static final Logger log = LoggerFactory.getLogger(Config.class);
    
    protected final String version;
    
    protected final List<NamedFactory<KeyExchange>> keyExchangeFactories;
    protected final List<NamedFactory<Cipher>> cipherFactories;
    protected final List<NamedFactory<Compression>> compressionFactories;
    protected final List<NamedFactory<MAC>> macFactories;
    protected final List<NamedFactory<Signature>> signatureFactories;
    protected final List<NamedFactory<FileKeyProvider>> fileKeyProviderFactories;
    protected final NamedFactory<Random> randomFactory;
    
    protected Config(Builder builder)
    {
        this.version = builder.version;
        this.keyExchangeFactories = Collections.unmodifiableList(builder.keyExchangeFactories);
        this.cipherFactories = Collections.unmodifiableList(builder.cipherFactories);
        this.compressionFactories = Collections.unmodifiableList(builder.compressionFactories);
        this.macFactories = Collections.unmodifiableList(builder.macFactories);
        this.signatureFactories = Collections.unmodifiableList(builder.signatureFactories);
        this.fileKeyProviderFactories = Collections.unmodifiableList(builder.fileKeyProviderFactories);
        this.randomFactory = builder.randomFactory;
    }
    
    /**
     * Retrieve the list of named factories for <code>Cipher</code>.
     * 
     * @return a list of named <code>Cipher</code> factories, never {@code null}
     */
    public List<NamedFactory<Cipher>> getCipherFactories()
    {
        return cipherFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>Compression</code>.
     * 
     * @return a list of named {@code Compression} factories, never {@code null}
     */
    public List<NamedFactory<Compression>> getCompressionFactories()
    {
        return compressionFactories;
    }
    
    /**
     * Retrieve the list of named factories for {@code FileKeyProvider}.
     * 
     * @return a list of named {@code FileKeyProvider} factories
     */
    public List<NamedFactory<FileKeyProvider>> getFileKeyProviderFactories()
    {
        return fileKeyProviderFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>KeyExchange</code>.
     * 
     * @return a list of named <code>KeyExchange</code> factories, never {@code null}
     */
    public List<NamedFactory<KeyExchange>> getKeyExchangeFactories()
    {
        return keyExchangeFactories;
    }
    
    /**
     * Retrieve the list of named factories for <code>MAC</code>.
     * 
     * @return a list of named <code>Mac</code> factories, never {@code null}
     */
    public List<NamedFactory<MAC>> getMACFactories()
    {
        return macFactories;
    }
    
    /**
     * Retrieve the {@link Random} factory to be used.
     * 
     * @return the {@link Random} factory, never {@code null}
     */
    public NamedFactory<Random> getRandomFactory()
    {
        return randomFactory;
    }
    
    /**
     * Retrieve the list of named factories for {@link Signature}
     * 
     * @return a list of named {@link Signature} factories, never {@code null}
     */
    public List<NamedFactory<Signature>> getSignatureFactories()
    {
        return signatureFactories;
    }
    
    public String getVersion()
    {
        return version;
    }
    
}
