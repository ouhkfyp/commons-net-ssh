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

import java.io.IOException;

import org.apache.commons.net.ssh.Constants;
import org.apache.commons.net.ssh.FactoryManager;
import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.cipher.Cipher;
import org.apache.commons.net.ssh.compression.Compression;
import org.apache.commons.net.ssh.digest.Digest;
import org.apache.commons.net.ssh.kex.KeyExchange;
import org.apache.commons.net.ssh.mac.MAC;
import org.apache.commons.net.ssh.util.Buffer;
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
        EXPECT_KEXINIT, EXPECT_FOLLOWUP, EXPECT_NEWKEYS, KEX_DONE
    };
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final Transport transport;
    private final FactoryManager fm;
    
    //
    // Key exchange support
    //
    private byte[] sessionID;
    private String[] serverProposal;
    private String[] clientProposal;
    private String[] negotiated; // negotiated algorithms
    private byte[] I_C; // the payload of our SSH_MSG_KEXINIT
    private byte[] I_S; // the payload of server's SSH_MSG_KEXINIT
    private KeyExchange kex;
    
    private State state = State.EXPECT_KEXINIT; // our initial state
    private volatile boolean sentKexInit = false;
    
    KexHandler(Transport transport)
    {
        this.transport = transport;
        fm = transport.getFactoryManager();
    }
    
    /**
     * Create our proposal for SSH negotiation
     * 
     * @param hostKeyTypes
     *            the list of supported host key types
     * @return an array of 10 strings holding this proposal
     */
    private String[] createProposal(String hostKeyTypes)
    {
        return new String[] { NamedFactory.Utils.getNames(fm.getKeyExchangeFactories()),
                hostKeyTypes, NamedFactory.Utils.getNames(fm.getCipherFactories()),
                NamedFactory.Utils.getNames(fm.getCipherFactories()),
                NamedFactory.Utils.getNames(fm.getMACFactories()),
                NamedFactory.Utils.getNames(fm.getMACFactories()),
                NamedFactory.Utils.getNames(fm.getCompressionFactories()),
                NamedFactory.Utils.getNames(fm.getCompressionFactories()), "", "" };
    }
    
    private void extractProposal(Buffer buffer) throws Exception
    {
        serverProposal = new String[Constants.PROPOSAL_MAX];
        // recreate the packet payload which will be needed at a later time
        byte[] d = buffer.array();
        I_S = new byte[buffer.available() + 1];
        I_S[0] = Constants.Message.SSH_MSG_KEXINIT.toByte();
        System.arraycopy(d, buffer.rpos(), I_S, 1, I_S.length - 1);
        // skip 16 bytes of random data
        buffer.rpos(buffer.rpos() + 16);
        // read proposal
        for (int i = 0; i < serverProposal.length; i++)
            serverProposal[i] = buffer.getString();
        // skip 5 bytes
        buffer.getByte();
        buffer.getInt();
    }
    
    private void gotKexInit(Buffer buffer) throws Exception
    {
        extractProposal(buffer);
        negotiate();
        kex = NamedFactory.Utils.create(fm.getKeyExchangeFactories(),
                negotiated[Constants.PROPOSAL_KEX_ALGS]);
        log.debug(transport.clientID);
        log.debug(transport.serverID);
        kex.init(transport, transport.serverID.getBytes(), transport.clientID.getBytes(), I_S, I_C);
    }
    
    /**
     * Put new keys into use. This method will intialize the ciphers, digests, MACs and compression
     * according to the negotiated server and client proposals.
     * 
     * @throws Exception
     *             if an error occurs
     */
    private void gotNewKeys() throws Exception
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
        
        Buffer buffer = new Buffer();
        buffer.putMPInt(K);
        buffer.putRawBytes(H);
        buffer.putByte((byte) 0x41);
        buffer.putRawBytes(sessionID);
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
        
        s2ccipher = NamedFactory.Utils.create(fm.getCipherFactories(),
                negotiated[Constants.PROPOSAL_ENC_ALGS_STOC]);
        Es2c = resizeKey(Es2c, s2ccipher.getBlockSize(), hash, K, H);
        s2ccipher.init(Cipher.Mode.Decrypt, Es2c, IVs2c);
        
        s2cmac = NamedFactory.Utils.create(fm.getMACFactories(),
                negotiated[Constants.PROPOSAL_MAC_ALGS_STOC]);
        s2cmac.init(MACs2c);
        
        c2scipher = NamedFactory.Utils.create(fm.getCipherFactories(),
                negotiated[Constants.PROPOSAL_ENC_ALGS_CTOS]);
        Ec2s = resizeKey(Ec2s, c2scipher.getBlockSize(), hash, K, H);
        c2scipher.init(Cipher.Mode.Encrypt, Ec2s, IVc2s);
        
        c2smac = NamedFactory.Utils.create(fm.getMACFactories(),
                negotiated[Constants.PROPOSAL_MAC_ALGS_CTOS]);
        c2smac.init(MACc2s);
        
        s2ccomp = NamedFactory.Utils.create(fm.getCompressionFactories(),
                negotiated[Constants.PROPOSAL_COMP_ALGS_STOC]);
        c2scomp = NamedFactory.Utils.create(fm.getCompressionFactories(),
                negotiated[Constants.PROPOSAL_COMP_ALGS_CTOS]);
        
        transport.bin.setClientToServer(c2scipher, c2smac, c2scomp);
        transport.bin.setServerToClient(s2ccipher, s2cmac, s2ccomp);
    }
    
    boolean handle(Constants.Message cmd, Buffer buffer) throws Exception
    {
        switch (state)
        {
        case EXPECT_KEXINIT:
            if (cmd != Constants.Message.SSH_MSG_KEXINIT) {
                log.error("Ignoring command " + cmd + " while waiting for "
                        + Constants.Message.SSH_MSG_KEXINIT);
                break;
            }
            log.info("Received SSH_MSG_KEXINIT");
            // make sure init() has been called; its a pre-requisite for negotiating
            while (!sentKexInit)
                ;
            gotKexInit(buffer);
            state = State.EXPECT_FOLLOWUP;
            break;
        case EXPECT_FOLLOWUP:
            log.info("Received kex followup data");
            buffer.rpos(buffer.rpos() - 1);
            if (kex.next(buffer)) {
                if (!transport.verifyHost(kex.getHostKey()))
                    throw new SSHException("Could not verify host key");
                sendNewKeys();
                state = State.EXPECT_NEWKEYS;
            }
            break;
        case EXPECT_NEWKEYS:
            if (cmd != Constants.Message.SSH_MSG_NEWKEYS) {
                transport.disconnect(Constants.SSH_DISCONNECT_PROTOCOL_ERROR,
                        "Protocol error: expected packet SSH_MSG_NEWKEYS, got " + cmd);
                break;
            }
            log.info("Received SSH_MSG_NEWKEYS");
            gotNewKeys();
            state = State.KEX_DONE;
            break;
        case KEX_DONE:
            if (cmd != Constants.Message.SSH_MSG_KEXINIT)
                throw new IllegalStateException("Asked to handle " + cmd
                        + ", was expecting SSH_MSG_KEXINIT for key re-exchange");
            log.info("Received SSH_MSG_KEXINIT, initiating re-exchange");
            sendKexInit();
            gotKexInit(buffer);
            state = State.EXPECT_FOLLOWUP;
            break;
        default:
            assert false;
        }
        return state == State.KEX_DONE ? true : false;
    }
    
    void init() throws IOException
    {
        sendKexInit();
        sentKexInit = true;
    }
    
    /**
     * Compute the negotiated proposals by merging the client and server proposal. The negotiated
     * proposal will be stored in the {@link #negotiated} property.
     */
    private void negotiate() throws SSHException
    {
        String[] guess = new String[Constants.PROPOSAL_MAX];
        for (int i = 0; i < Constants.PROPOSAL_MAX; i++) {
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
            if (guess[i] == null && i != Constants.PROPOSAL_LANG_CTOS
                    && i != Constants.PROPOSAL_LANG_STOC)
                throw new SSHException("Unable to negotiate");
        }
        negotiated = guess;
        
        log.info("Negotiated (Cipher, MAC, Compression) --- client -> server: ("
                + negotiated[Constants.PROPOSAL_ENC_ALGS_CTOS] + ", "
                + negotiated[Constants.PROPOSAL_MAC_ALGS_CTOS] + ", "
                + negotiated[Constants.PROPOSAL_COMP_ALGS_CTOS] + ") --- server -> client: ("
                + negotiated[Constants.PROPOSAL_ENC_ALGS_STOC] + ", "
                + negotiated[Constants.PROPOSAL_MAC_ALGS_STOC] + ", "
                + negotiated[Constants.PROPOSAL_COMP_ALGS_STOC] + ")");
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
     * @throws Exception
     *             if a problem occur while resizing the key
     */
    private byte[] resizeKey(byte[] E, int blockSize, Digest hash, byte[] K, byte[] H)
            throws Exception
    {
        while (blockSize > E.length) {
            Buffer buffer = new Buffer();
            buffer.putMPInt(K);
            buffer.putRawBytes(H);
            buffer.putRawBytes(E);
            hash.update(buffer.array(), 0, buffer.available());
            byte[] foo = hash.digest();
            byte[] bar = new byte[E.length + foo.length];
            System.arraycopy(E, 0, bar, 0, E.length);
            System.arraycopy(foo, 0, bar, E.length, foo.length);
            E = bar;
        }
        return E;
    }
    
    /**
     * Send the key exchange initialization packet.
     */
    private void sendKexInit() throws IOException
    {
        clientProposal = createProposal(Constants.SSH_RSA + "," + Constants.SSH_DSS);
        Buffer buffer = transport.createBuffer(Constants.Message.SSH_MSG_KEXINIT);
        int p = buffer.wpos();
        buffer.wpos(p + 16);
        transport.prng.fill(buffer.array(), p, 16);
        for (String s : clientProposal)
            buffer.putString(s);
        buffer.putByte((byte) 0);
        buffer.putInt(0);
        byte[] data = buffer.getCompactData();
        log.info("Sending SSH_MSG_KEXINIT");
        transport.writePacket(buffer);
        I_C = data;
    }
    
    private void sendNewKeys() throws IOException
    {
        log.info("Sending SSH_MSG_NEWKEYS");
        transport.writePacket(transport.createBuffer(Constants.Message.SSH_MSG_NEWKEYS));
    }
    
}
