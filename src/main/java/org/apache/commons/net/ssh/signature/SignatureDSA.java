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

import java.security.SignatureException;

import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.util.Constants.KeyType;

/**
 * DSA {@link Signature}
 */
public class SignatureDSA extends AbstractSignature
{
    
    /**
     * A named factory for DSA signature
     */
    public static class Factory implements org.apache.commons.net.ssh.Factory.Named<Signature>
    {
        
        public Signature create()
        {
            return new SignatureDSA();
        }
        
        public String getName()
        {
            return KeyType.DSA.toString();
        }
        
    }
    
    public SignatureDSA()
    {
        super("SHA1withDSA");
    }
    
    public byte[] sign()
    {
        byte[] sig;
        try
        {
            sig = signature.sign();
        } catch (SignatureException e)
        {
            throw new SSHRuntimeException(e);
        }
        
        // sig is in ASN.1
        // SEQUENCE::={ r INTEGER, s INTEGER }
        int len = 0;
        int index = 3;
        len = sig[index++] & 0xff;
        byte[] r = new byte[len];
        System.arraycopy(sig, index, r, 0, r.length);
        index = index + len + 1;
        len = sig[index++] & 0xff;
        byte[] s = new byte[len];
        System.arraycopy(sig, index, s, 0, s.length);
        
        byte[] result = new byte[40];
        
        // result must be 40 bytes, but length of r and s may not be 20 bytes
        
        System.arraycopy(r, r.length > 20 ? 1 : 0, result, r.length > 20 ? 0 : 20 - r.length, r.length > 20 ? 20
                : r.length);
        System.arraycopy(s, s.length > 20 ? 1 : 0, result, s.length > 20 ? 20 : 40 - s.length, s.length > 20 ? 20
                : s.length);
        
        return result;
    }
    
    public boolean verify(byte[] sig)
    {
        sig = extractSig(sig);
        
        // ASN.1
        int frst = (sig[0] & 0x80) != 0 ? 1 : 0;
        int scnd = (sig[20] & 0x80) != 0 ? 1 : 0;
        
        int length = sig.length + 6 + frst + scnd;
        byte[] tmp = new byte[length];
        tmp[0] = (byte) 0x30;
        tmp[1] = (byte) 0x2c;
        tmp[1] += frst;
        tmp[1] += scnd;
        tmp[2] = (byte) 0x02;
        tmp[3] = (byte) 0x14;
        tmp[3] += frst;
        System.arraycopy(sig, 0, tmp, 4 + frst, 20);
        tmp[4 + tmp[3]] = (byte) 0x02;
        tmp[5 + tmp[3]] = (byte) 0x14;
        tmp[5 + tmp[3]] += scnd;
        System.arraycopy(sig, 20, tmp, 6 + tmp[3] + scnd, 20);
        sig = tmp;
        
        try
        {
            return signature.verify(sig);
        } catch (SignatureException e)
        {
            throw new SSHRuntimeException(e);
        }
    }
    
}
