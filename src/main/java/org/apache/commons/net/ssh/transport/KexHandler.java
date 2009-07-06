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
import org.apache.commons.net.ssh.TransportException;
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
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
class KexHandler
{
    
    private enum State
    {
        EXPECT_KEXINIT, // we have sent or are sending KEXINIT, and expect the server's KEXINIT
        EXPECT_FOLLOWUP, // we are expecting some followup data as part of the exchange 
        EXPECT_NEWKEYS, // we are expecting SSH_MSG_NEWKEYS
        KEX_DONE, // key exchange has completed for now; but will be reinitiated if we get a KEXINIT
    }
    
    //
    // Values for the algorithm negotiation
    //
    private static final int PROPOSAL_KEX_ALGS = 0;
    // private static final int PROPOSAL_SERVER_HOST_KEY_ALGS = 1; --- UNUSED
    private static final int PROPOSAL_ENC_ALGS_CTOS = 2;
    private static final int PROPOSAL_ENC_ALGS_STOC = 3;
    private static final int PROPOSAL_MAC_ALGS_CTOS = 4;
    private static final int PROPOSAL_MAC_ALGS_STOC = 5;
    private static final int PROPOSAL_COMP_ALGS_CTOS = 6;
    private static final int PROPOSAL_COMP_ALGS_STOC = 7;
    private static final int PROPOSAL_LANG_CTOS = 8;
    private static final int PROPOSAL_LANG_STOC = 9;
    private static final int PROPOSAL_MAX = 10;
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final Transport transport;
    private final FactoryManager fm;
    
    //
    // Key exchange support
    //
    byte[] sessionID;
    private String[] serverProposal;
    private String[] clientProposal;
    private String[] negotiated; // negotiated algorithms
    private byte[] I_C; // the payload of our SSH_MSG_KEXINIT
    private byte[] I_S; // the payload of server's SSH_MSG_KEXINIT
    private KeyExchange kex;
    
    private State state = State.EXPECT_KEXINIT; // our initial state
    
    /*
     * There must be a release (implying KEXINIT sent) before we process received KEXINIT and negotiate algorithms.
     */
    private final Semaphore initSent = new Semaphore(0);
    
    KexHandler(Transport transport)
    {
        this.transport = transport;
        fm = transport.getFactoryManager();
    }
    
    /**
     * Create our proposal for SSH negotiation
     * 
     * @return an array of 10 strings holding this proposal
     */
    private String[] createProposal()
    {
        return new String[] { NamedFactory.Utils.getNames(fm.getKeyExchangeFactories()), // PROPOSAL_KEX_ALGS 
                NamedFactory.Utils.getNames(fm.getSignatureFactories()), // PROPOSAL_SERVER_HOST_KEY_ALGS 
                NamedFactory.Utils.getNames(fm.getCipherFactories()), // PROPOSAL_ENC_ALGS_CTOS
                NamedFactory.Utils.getNames(fm.getCipherFactories()), // PROPOSAL_ENC_ALGS_CTOS
                NamedFactory.Utils.getNames(fm.getMACFactories()), // PROPOSAL_MAC_ALGS_CTOS
                NamedFactory.Utils.getNames(fm.getMACFactories()), // PROPOSAL_MAC_ALGS_STOC
                NamedFactory.Utils.getNames(fm.getCompressionFactories()), // PROPOSAL_MAC_ALGS_STOC
                NamedFactory.Utils.getNames(fm.getCompressionFactories()), // PROPOSAL_COMP_ALGS_STOC
                "", // PROPOSAL_COMP_ALGS_STOC (optional) 
                "" }; // PROPOSAL_LANG_STOC (optional)
    }
    
    private void extractProposal(Buffer buffer)
    {
        serverProposal = new String[PROPOSAL_MAX];
        
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
        
        //        // skip 5 bytes
        //        buffer.getByte();
        //        buffer.getInt();
    }
    
    private void gotKexInit(Buffer buffer) throws TransportException
    {
        extractProposal(buffer);
        negotiate();
        kex = NamedFactory.Utils.create(fm.getKeyExchangeFactories(), negotiated[PROPOSAL_KEX_ALGS]);
        kex.init(transport, transport.serverID.getBytes(), transport.clientID.getBytes(), I_S, I_C);
    }
    
    /**
     * Put new keys into use. This method will intialize the ciphers, digests, MACs and compression according to the
     * negotiated server and client proposals.
     */
    private void gotNewKeys()
    {
        byte[] IVc2s;
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
        
        s2ccipher = NamedFactory.Utils.create(fm.getCipherFactories(), negotiated[PROPOSAL_ENC_ALGS_STOC]);
        Es2c = resizeKey(Es2c, s2ccipher.getBlockSize(), hash, K, H);
        s2ccipher.init(Cipher.Mode.Decrypt, Es2c, IVs2c);
        
        s2cmac = NamedFactory.Utils.create(fm.getMACFactories(), negotiated[PROPOSAL_MAC_ALGS_STOC]);
        s2cmac.init(MACs2c);
        
        c2scipher = NamedFactory.Utils.create(fm.getCipherFactories(), negotiated[PROPOSAL_ENC_ALGS_CTOS]);
        Ec2s = resizeKey(Ec2s, c2scipher.getBlockSize(), hash, K, H);
        c2scipher.init(Cipher.Mode.Encrypt, Ec2s, IVc2s);
        
        c2smac = NamedFactory.Utils.create(fm.getMACFactories(), negotiated[PROPOSAL_MAC_ALGS_CTOS]);
        c2smac.init(MACc2s);
        
        s2ccomp = NamedFactory.Utils.create(fm.getCompressionFactories(), negotiated[PROPOSAL_COMP_ALGS_STOC]);
        c2scomp = NamedFactory.Utils.create(fm.getCompressionFactories(), negotiated[PROPOSAL_COMP_ALGS_CTOS]);
        
        transport.bin.setClientToServer(c2scipher, c2smac, c2scomp);
        transport.bin.setServerToClient(s2ccipher, s2cmac, s2ccomp);
    }
    
    /**
     * Compute the negotiated proposals by merging the client and server proposal. The negotiated proposal will be
     * stored in the {@link #negotiated} property.
     */
    private void negotiate() throws TransportException
    {
        String[] guess = new String[PROPOSAL_MAX];
        for (int i = 0; i < PROPOSAL_MAX; i++) {
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
            if (guess[i] == null && i != PROPOSAL_LANG_CTOS && i != PROPOSAL_LANG_STOC)
                throw new TransportException("Unable to negotiate");
        }
        negotiated = guess;
        
        log.info("Negotiated algorithms: client -> server = (" + negotiated[PROPOSAL_ENC_ALGS_CTOS] + ", "
                + negotiated[PROPOSAL_MAC_ALGS_CTOS] + ", " + negotiated[PROPOSAL_COMP_ALGS_CTOS]
                + "); server -> client = (" + negotiated[PROPOSAL_ENC_ALGS_STOC] + ", "
                + negotiated[PROPOSAL_MAC_ALGS_STOC] + ", " + negotiated[PROPOSAL_COMP_ALGS_STOC] + ")");
    }
    
    /**
     * Private method used while putting new keys into use that will resize the key used to initialize the cipher to the
     * needed length.
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
        clientProposal = createProposal();
        Buffer buffer = new Buffer(Message.KEXINIT);
        int p = buffer.wpos();
        buffer.wpos(p + 16);
        transport.prng.fill(buffer.array(), p, 16); // cookie
        for (String s : clientProposal)
            // the 10 name-lists
            buffer.putString(s);
        buffer.putBoolean(false) // optimistic next packet does not follow
              .putInt(0); // "reserved" for future
        byte[] data = buffer.getCompactData();
        log.info("Sending SSH_MSG_KEXINIT");
        transport.writePacket(buffer);
        I_C = data;
    }
    
    private void sendNewKeys() throws TransportException
    {
        log.info("Sending SSH_MSG_NEWKEYS");
        transport.writePacket(new Buffer(Message.NEWKEYS));
    }
    
    boolean handle(Message cmd, Buffer buffer) throws TransportException
    {
        /*
         * Thread context = Transport.inPump
         */
        switch (state)
        {
        case EXPECT_KEXINIT:
            if (cmd != Message.KEXINIT) {
                log.error("Ignoring command " + cmd + " while waiting for " + Message.KEXINIT);
                break;
            }
            log.info("Received SSH_MSG_KEXINIT");
            // make sure init() has been called; its a pre-requisite for negotiating
            try {
                initSent.acquire();
            } catch (InterruptedException e) {
                throw new TransportException(e);
            }
            gotKexInit(buffer);
            state = State.EXPECT_FOLLOWUP;
            break;
        case EXPECT_FOLLOWUP:
            log.info("Received kex followup data");
            buffer.rpos(buffer.rpos() - 1);
            if (kex.next(buffer)) {
                // kex is done; now verify host key
                PublicKey hostKey = kex.getHostKey();
                if (!transport.verifyHost(hostKey))
                    throw new TransportException(DisconnectReason.HOST_KEY_NOT_VERIFIABLE, "Could not verify ["
                            + KeyType.fromKey(hostKey) + "] host key with fingerprint ["
                            + SecurityUtils.getFingerprint(hostKey) + "]");
                sendNewKeys(); // declare all is well
                state = State.EXPECT_NEWKEYS; // expect server to tell us the same thing
            }
            break;
        case EXPECT_NEWKEYS:
            if (cmd != Message.NEWKEYS)
                throw new TransportException(DisconnectReason.PROTOCOL_ERROR,
                                             "Protocol error: expected packet SSH_MSG_NEWKEYS, got " + cmd);
            log.info("Received SSH_MSG_NEWKEYS");
            gotNewKeys();
            state = State.KEX_DONE;
            if (transport.writeLock.isHeldByCurrentThread()) // is held for re-exchange, se below
                transport.writeLock.unlock();
            break;
        case KEX_DONE:
            if (cmd != Message.KEXINIT)
                throw new IllegalStateException("Asked to handle " + cmd
                        + ", was expecting SSH_MSG_KEXINIT for key re-exchange");
            log.info("Received SSH_MSG_KEXINIT, initiating re-exchange");
            transport.writeLock.lock(); // prevent other packets being sent while re-ex is ongoing
            sendKexInit();
            gotKexInit(buffer);
            state = State.EXPECT_FOLLOWUP;
            break;
        default:
            assert false;
        }
        return state == State.KEX_DONE ? true : false;
    }
    
    void init() throws TransportException
    {
        sendKexInit();
        initSent.release();
    }
    
}
