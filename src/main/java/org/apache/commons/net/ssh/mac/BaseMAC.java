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
package org.apache.commons.net.ssh.mac;

import java.security.GeneralSecurityException;

import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.util.SecurityUtils;

/**
 * Base class for <code>Mac</code> implementations based on the JCE provider.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class BaseMAC implements MAC
{
    
    private final String algorithm;
    private final int defbsize;
    private final int bsize;
    private final byte[] tmp;
    private javax.crypto.Mac mac;
    
    public BaseMAC(String algorithm, int bsize, int defbsize)
    {
        this.algorithm = algorithm;
        this.bsize = bsize;
        this.defbsize = defbsize;
        tmp = new byte[defbsize];
    }
    
    public byte[] doFinal()
    {
        return mac.doFinal();
    }
    
    public byte[] doFinal(byte[] input)
    {
        return mac.doFinal(input);
    }
    
    public void doFinal(byte[] buf, int offset)
    {
        try {
            if (bsize != defbsize) {
                mac.doFinal(tmp, 0);
                System.arraycopy(tmp, 0, buf, offset, bsize);
            } else
                mac.doFinal(buf, offset);
        } catch (ShortBufferException e) {
            throw new SSHRuntimeException(e);
        }
    }
    
    public int getBlockSize()
    {
        return bsize;
    }
    
    public void init(byte[] key)
    {
        if (key.length > defbsize) {
            byte[] tmp = new byte[defbsize];
            System.arraycopy(key, 0, tmp, 0, defbsize);
            key = tmp;
        }
        
        SecretKeySpec skey = new SecretKeySpec(key, algorithm);
        try {
            mac = SecurityUtils.getMAC(algorithm);
            mac.init(skey);
        } catch (GeneralSecurityException e) {
            throw new SSHRuntimeException(e);
        }
    }
    
    public void update(byte foo[], int s, int l)
    {
        mac.update(foo, s, l);
    }
    
    public void update(byte[] foo)
    {
        mac.update(foo, 0, foo.length);
    }
    
    public void update(long i)
    {
        tmp[0] = (byte) (i >>> 24);
        tmp[1] = (byte) (i >>> 16);
        tmp[2] = (byte) (i >>> 8);
        tmp[3] = (byte) i;
        update(tmp, 0, 4);
    }
    
}
