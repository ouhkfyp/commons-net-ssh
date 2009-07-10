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
package org.apache.commons.net.ssh.signature;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.util.SecurityUtils;

/**
 * An abstract class for {@link Signature} that implements common functionality.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public abstract class AbstractSignature implements Signature
{
    
    protected java.security.Signature signature;
    protected String algorithm;
    
    protected AbstractSignature(String algorithm)
    {
        this.algorithm = algorithm;
    }
    
    public void init(PublicKey pubkey, PrivateKey prvkey)
    {
        try {
            signature = SecurityUtils.getSignature(algorithm);
            if (pubkey != null)
                signature.initVerify(pubkey);
            if (prvkey != null)
                signature.initSign(prvkey);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
    }
    
    public void update(byte[] foo)
    {
        update(foo, 0, foo.length);
    }
    
    public void update(byte[] foo, int off, int len)
    {
        try {
            signature.update(foo, off, len);
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }
    
    protected byte[] extractSig(byte[] sig)
    {
        if (sig[0] == 0 && sig[1] == 0 && sig[2] == 0) {
            int i = 0;
            int j;
            j =
                    sig[i++] << 24 & 0xff000000 | sig[i++] << 16 & 0x00ff0000 | sig[i++] << 8 & 0x0000ff00 | sig[i++]
                            & 0x000000ff;
            i += j;
            j =
                    sig[i++] << 24 & 0xff000000 | sig[i++] << 16 & 0x00ff0000 | sig[i++] << 8 & 0x0000ff00 | sig[i++]
                            & 0x000000ff;
            byte[] tmp = new byte[j];
            System.arraycopy(sig, i, tmp, 0, j);
            sig = tmp;
        }
        return sig;
    }
}
