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
package org.apache.commons.net.ssh.kex;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.net.ssh.Digest;
import org.apache.commons.net.ssh.KeyExchange;
import org.apache.commons.net.ssh.KeyPairProvider;
import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.Signature;
import org.apache.commons.net.ssh.SSHConstants;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.digest.SHA1;
import org.apache.commons.net.ssh.kex.DH;
import org.apache.commons.net.ssh.trans.Transport;
import org.apache.commons.net.ssh.util.Buffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base class for DHG key exchange algorithms.
 * Implementations will only have to configure the required data on the
 * {@link DH} class in the {@link #initDH(org.apache.sshd.common.kex.DH)} method.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractDHG implements KeyExchange {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private Transport session;
    private byte[] V_S;
    private byte[] V_C;
    private byte[] I_S;
    private byte[] I_C;
    private Digest sha;
    private DH dh;
    private byte[] e;
    private byte[] f;
    private byte[] K;
    private byte[] H;
    private PublicKey hostKey;

    public void init(Transport session, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C) throws Exception {
        this.session = session;
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;
        sha = new SHA1();
        sha.init();
        dh = new DH();
        initDH(dh);
        e = dh.getE();

        log.info("Sending SSH_MSG_KEXDH_INIT");
        Buffer buffer = session.createBuffer(SSHConstants.Message.SSH_MSG_KEXDH_INIT);
        buffer.putMPInt(e);
        session.writePacket(buffer);
    }

    protected abstract void initDH(DH dh);

    public boolean next(Buffer buffer) throws Exception {
        SSHConstants.Message cmd = buffer.getCommand();
        if (cmd != SSHConstants.Message.SSH_MSG_KEXDH_REPLY_KEX_DH_GEX_GROUP) {
            throw new SSHException(SSHConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                                   "Protocol error: expected packet " + SSHConstants.Message.SSH_MSG_KEXDH_REPLY_KEX_DH_GEX_GROUP + ", got " + cmd);
        }

        log.info("Received SSH_MSG_KEXDH_REPLY");
        
        byte[] K_S = buffer.getBytes();
        f = buffer.getMPIntAsBytes();
        byte[] sig = buffer.getBytes();
        dh.setF(f);
        K = dh.getK();

        buffer = new Buffer(K_S);
        hostKey = buffer.getPublicKey();
        String keyAlg = (hostKey instanceof RSAPublicKey) ? KeyPairProvider.SSH_RSA : KeyPairProvider.SSH_DSS;

        buffer = new Buffer();
        buffer.putString(V_C);
        buffer.putString(V_S);
        buffer.putString(I_C);
        buffer.putString(I_S);
        buffer.putString(K_S);
        buffer.putMPInt(e);
        buffer.putMPInt(f);
        buffer.putMPInt(K);
        sha.update(buffer.array(), 0, buffer.available());
        H = sha.digest();

        Signature verif = NamedFactory.Utils.create(session.getFactoryManager().getSignatureFactories(), keyAlg);
        verif.init(hostKey, null);
        verif.update(H, 0, H.length);
        if (!verif.verify(sig)) {
            throw new SSHException(SSHConstants.SSH_DISCONNECT_KEY_EXCHANGE_FAILED,
                                   "KeyExchange signature verification failed");
        }
        return true;
    }

    public Digest getHash() {
        return sha;
    }

    public byte[] getH() {
        return H;
    }

    public byte[] getK() {
        return K;
    }
    
    public PublicKey getHostKey() {
        return hostKey;
    }
    

}