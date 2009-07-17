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
package org.apache.commons.net.ssh.transport;

import java.security.PublicKey;
import java.util.concurrent.Semaphore;

import org.apache.commons.net.ssh.FactoryManager;
import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.cipher.Cipher;
import org.apache.commons.net.ssh.compression.Compression;
import org.apache.commons.net.ssh.digest.Digest;
import org.apache.commons.net.ssh.kex.KeyExchange;
import org.apache.commons.net.ssh.mac.MAC;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.SecurityUtils;
import org.apache.commons.net.ssh.util.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Constants.KeyType;
import org.apache.commons.net.ssh.util.Constants.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Algorithm negotiation and key exchange
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
class Negotiator
{
    
    private enum State
    {
        EXPECT_KEXINIT, // we have sent or are sending KEXINIT, and expect the server's KEXINIT
        EXPECT_FOLLOWUP, // we are expecting some followup data as part of the exchange 
        EXPECT_NEWKEYS, // we are expecting SSH_MSG_NEWKEYS
        KEX_DONE, // key exchange has completed for now; but will be reinitiated if we get a KEXINIT
    }
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final TransportProtocol trans;
    private final FactoryManager fm;
    
    /** Current state */
    private State state;
    
    /**
     * There must be a release (implying KEXINIT sent) before we process received KEXINIT and
     * negotiate algorithms.
     */
    private final Semaphore initSent = new Semaphore(0);
    
    /** Computed session ID */
    byte[] sessionID;
    
    /** Negotiated algorithms */
    private String[] negotiated;
    /** Server's proposed algorithms - each string comma-delimited in order of preference */
    private String[] serverProposal;
    /** Client's proposed algorithms - each string comma-delimited in order of preference */
    private String[] clientProposal;
    
    // Friendlier names for array indexes w.r.t the above 3 arrays
    private static final int PROP_KEX_ALG = 0;
    private static final int PROP_SRVR_HOST_KEY_ALG = 1;
    private static final int PROP_ENC_ALG_C2S = 2;
    private static final int PROP_ENC_ALG_S2C = 3;
    private static final int PROP_MAC_ALG_C2S = 4;
    private static final int PROP_MAC_ALG_S2C = 5;
    private static final int PROP_COMP_ALG_C2S = 6;
    private static final int PROP_COMP_ALG_S2C = 7;
    private static final int PROP_LANG_C2S = 8;
    private static final int PROP_LANG_S2C = 9;
    private static final int PROP_MAX = 10;
    
    /** Instance of negotiated key exchange algorithm */
    private KeyExchange kex;
    /** Payload of our SSH_MSG_KEXINIT; is passed on to the KeyExchange alg */
    private byte[] I_C;
    /** Payload of server's SSH_MSG_KEXINIT; is passed on to the KeyExchange alg */
    private byte[] I_S;
    
    Negotiator(TransportProtocol transport)
    {
        this.trans = transport;
        fm = transport.getFactoryManager();
        state = State.EXPECT_KEXINIT;
    }
    
    /**
     * Create our proposal for SSH negotiation
     * 
     * @return an array of 10 strings holding this proposal
     */
    private String[] createProposal()
    {
        return new String[] { //
        NamedFactory.Utils.getNames(fm.getKeyExchangeFactories()), // PROP_KEX_ALG 
                NamedFactory.Utils.getNames(fm.getSignatureFactories()), // PROP_SRVR_HOST_KEY_ALG
                NamedFactory.Utils.getNames(fm.getCipherFactories()), // PROP_ENC_ALG_C2S
                NamedFactory.Utils.getNames(fm.getCipherFactories()), // PROP_ENC_ALG_S2C
                NamedFactory.Utils.getNames(fm.getMACFactories()), // PROP_MAC_ALG_C2S
                NamedFactory.Utils.getNames(fm.getMACFactories()), // PROP_MAC_ALG_S2C
                NamedFactory.Utils.getNames(fm.getCompressionFactories()), // PROP_MAC_ALG_C2S
                NamedFactory.Utils.getNames(fm.getCompressionFactories()), // PROP_COMP_ALG_S2C
                "", // PROP_LANG_C2S (optional, thus empty string) 
                "" // PROP_LANG_S2C (optional, thus empty string) 
        };
    }
    
    private void extractProposal(Buffer buffer)
    {
        serverProposal = new String[PROP_MAX];
        // recreate the packet payload which will be needed at a later time
        byte[] d = buffer.array();
        I_S = new byte[buffer.available() + 1];
        I_S[0] = Message.KEXINIT.toByte();
        System.arraycopy(d, buffer.rpos(), I_S, 1, I_S.length - 1);
        // skip 16 bytes of random data
        buffer.rpos(buffer.rpos() + 16);
        // read proposal
        for (int i = 0; i < serverProposal.length; i++)
            serverProposal[i] = buffer.getString();
    }
    
    private void gotKexInit(Buffer buffer) throws TransportException
    {
        extractProposal(buffer);
        negotiate();
        kex = NamedFactory.Utils.create(fm.getKeyExchangeFactories(), negotiated[PROP_KEX_ALG]);
        kex.init(trans, trans.serverID.getBytes(), trans.clientID.getBytes(), I_S, I_C);
    }
    
    /**
     * Put new keys into use. This method will intialize the ciphers, digests, MACs and compression
     * according to the negotiated server and client proposals.
     */
    private void gotNewKeys()
    {
        byte[] IVc2s; // IV = initialization vector
        byte[] IVs2c;
        byte[] Ec2s;
        byte[] Es2c;
        byte[] MACc2s;
        byte[] MACs2c;
        byte[] K = kex.getK();
        byte[] H = kex.getH();
        Digest hash = kex.getHash();
        Cipher s2ccipher;
        Cipher c2scipher;
        MAC s2cmac;
        MAC c2smac;
        Compression s2ccomp;
        Compression c2scomp;
        
        if (sessionID == null) {
            sessionID = new byte[H.length];
            System.arraycopy(H, 0, sessionID, 0, H.length);
        }
        
        Buffer buffer = new Buffer().putMPInt(K) //
                                    .putRawBytes(H) //
                                    .putByte((byte) 0x41) //
                                    .putRawBytes(sessionID);
        int pos = buffer.available();
        byte[] buf = buffer.array();
        hash.update(buf, 0, pos);
        IVc2s = hash.digest();
        
        int j = pos - sessionID.length - 1;
        
        buf[j]++;
        hash.update(buf, 0, pos);
        IVs2c = hash.digest();
        
        buf[j]++;
        hash.update(buf, 0, pos);
        Ec2s = hash.digest();
        
        buf[j]++;
        hash.update(buf, 0, pos);
        Es2c = hash.digest();
        
        buf[j]++;
        hash.update(buf, 0, pos);
        MACc2s = hash.digest();
        
        buf[j]++;
        hash.update(buf, 0, pos);
        MACs2c = hash.digest();
        
        s2ccipher = NamedFactory.Utils.create(fm.getCipherFactories(), negotiated[PROP_ENC_ALG_S2C]);
        Es2c = resizeKey(Es2c, s2ccipher.getBlockSize(), hash, K, H);
        s2ccipher.init(Cipher.Mode.Decrypt, Es2c, IVs2c);
        
        s2cmac = NamedFactory.Utils.create(fm.getMACFactories(), negotiated[PROP_MAC_ALG_S2C]);
        s2cmac.init(MACs2c);
        
        c2scipher = NamedFactory.Utils.create(fm.getCipherFactories(), negotiated[PROP_ENC_ALG_C2S]);
        Ec2s = resizeKey(Ec2s, c2scipher.getBlockSize(), hash, K, H);
        c2scipher.init(Cipher.Mode.Encrypt, Ec2s, IVc2s);
        
        c2smac = NamedFactory.Utils.create(fm.getMACFactories(), negotiated[PROP_MAC_ALG_C2S]);
        c2smac.init(MACc2s);
        
        s2ccomp = NamedFactory.Utils.create(fm.getCompressionFactories(), negotiated[PROP_COMP_ALG_S2C]);
        c2scomp = NamedFactory.Utils.create(fm.getCompressionFactories(), negotiated[PROP_COMP_ALG_C2S]);
        
        trans.packetConverter.setClientToServer(c2scipher, c2smac, c2scomp);
        trans.packetConverter.setServerToClient(s2ccipher, s2cmac, s2ccomp);
    }
    
    /**
     * Compute the negotiated proposals by merging the client and server proposal. The negotiated
     * proposal will be stored in the {@link #negotiated} field.
     */
    private void negotiate() throws TransportException
    {
        String[] guess = new String[PROP_MAX];
        for (int i = 0; i < PROP_MAX; i++) {
            String[] c = clientProposal[i].split(",");
            String[] s = serverProposal[i].split(",");
            for (String ci : c) {
                for (String si : s)
                    if (ci.equals(si)) {
                        guess[i] = ci;
                        break;
                    }
                if (guess[i] != null)
                    break;
            }
            if (guess[i] == null && i != PROP_LANG_C2S && i != PROP_LANG_S2C)
                throw new TransportException("Unable to negotiate");
        }
        negotiated = guess;
        
        log.info("Negotiated algorithms: client -> server = (" + negotiated[PROP_ENC_ALG_C2S] + ", "
                + negotiated[PROP_MAC_ALG_C2S] + ", " + negotiated[PROP_COMP_ALG_C2S] + ") | server -> client = ("
                + negotiated[PROP_ENC_ALG_S2C] + ", " + negotiated[PROP_MAC_ALG_S2C] + ", "
                + negotiated[PROP_COMP_ALG_S2C] + ")");
    }
    
    /**
     * Private method used while putting new keys into use that will resize the key used to
     * initialize the cipher to the needed length.
     * 
     * @param E
     *            the key to resize
     * @param blockSize
     *            the cipher block size
     * @param hash
     *            the hash algorithm
     * @param K
     *            the key exchange K parameter
     * @param H
     *            the key exchange H parameter
     * @return the resized key
     */
    private byte[] resizeKey(byte[] E, int blockSize, Digest hash, byte[] K, byte[] H)
    {
        while (blockSize > E.length) {
            Buffer buffer = new Buffer().putMPInt(K) //
                                        .putRawBytes(H) //
                                        .putRawBytes(E);
            hash.update(buffer.array(), 0, buffer.available());
            byte[] foo = hash.digest();
            byte[] bar = new byte[E.length + foo.length];
            System.arraycopy(E, 0, bar, 0, E.length);
            System.arraycopy(foo, 0, bar, E.length, foo.length);
            E = bar;
        }
        return E;
    }
    
    private void sendKexInit() throws TransportException
    {
        Buffer buf = new Buffer(Message.KEXINIT);
        
        // Put cookie
        int p = buf.wpos();
        buf.wpos(p + 16);
        trans.prng.fill(buf.array(), p, 16);
        
        // Put the 10 algorithm name-list's
        for (String s : clientProposal = createProposal())
            buf.putString(s);
        
        buf.putBoolean(false) // Optimistic next packet does not follow
           .putInt(0); // "Reserved" for future by spec
        
        I_C = buf.getCompactData(); // Store for future
        
        log.info("Sending SSH_MSG_KEXINIT");
        trans.writePacket(buf);
        
        // Declare SSH_MSG_KEXINIT sent
        initSent.release();
    }
    
    private void sendNewKeys() throws TransportException
    {
        log.info("Sending SSH_MSG_NEWKEYS");
        trans.writePacket(new Buffer(Message.NEWKEYS));
    }
    
    boolean handle(Message cmd, Buffer buffer) throws TransportException
    {
        switch (state)
        {
        case KEX_DONE:
        {
            assert cmd == Message.KEXINIT;
            // Re-exchange should commence
            sendKexInit();
            // Deliberate fall-through
        }
        case EXPECT_KEXINIT:
        {
            if (cmd != Message.KEXINIT) {
                trans.sendUnimplemented();
                break;
            }
            log.info("Received SSH_MSG_KEXINIT");
            // Make sure we have sent SSH_MSG_KEXINIT - it is a pre-requisite for negotiating 
            try {
                initSent.acquire();
            } catch (InterruptedException e) {
                throw new TransportException(e);
            }
            gotKexInit(buffer);
            // State transition - expect kex followup data
            state = State.EXPECT_FOLLOWUP;
            break;
        }
        case EXPECT_FOLLOWUP:
        {
            log.info("Received kex followup data");
            buffer.rpos(buffer.rpos() - 1);
            if (kex.next(buffer)) {
                // Basically done; now verify host key
                PublicKey hostKey = kex.getHostKey();
                if (!trans.verifyHost(hostKey))
                    throw new TransportException(DisconnectReason.HOST_KEY_NOT_VERIFIABLE, "Could not verify ["
                            + KeyType.fromKey(hostKey) + "] host key with fingerprint ["
                            + SecurityUtils.getFingerprint(hostKey) + "]");
                // Declare all is well
                sendNewKeys();
                // State transition - expect server to tell us the same thing
                state = State.EXPECT_NEWKEYS;
            }
            break;
        }
        case EXPECT_NEWKEYS:
        {
            if (cmd != Message.NEWKEYS)
                throw new TransportException(DisconnectReason.PROTOCOL_ERROR,
                                             "Protocol error: expected packet SSH_MSG_NEWKEYS, got " + cmd);
            log.info("Received SSH_MSG_NEWKEYS");
            gotNewKeys();
            // State transition - the whole process is complete
            state = State.KEX_DONE;
            break;
        }
        default:
            assert false;
        }
        return state == State.KEX_DONE;
    }
    
    void init() throws TransportException
    {
        sendKexInit();
    }
    
}
