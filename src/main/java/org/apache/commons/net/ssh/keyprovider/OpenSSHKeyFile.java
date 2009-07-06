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
package org.apache.commons.net.ssh.keyprovider;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.util.Base64;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.Constants.KeyType;

/**
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class OpenSSHKeyFile extends PKCS8KeyFile
{
    
    public static class Factory implements NamedFactory<FileKeyProvider>
    {
        
        public FileKeyProvider create()
        {
            return new OpenSSHKeyFile();
        }
        
        public String getName()
        {
            return "OpenSSH";
        }
    }
    
    private PublicKey pubKey;
    
    @Override
    public PublicKey getPublic() throws IOException
    {
        return pubKey != null ? pubKey : super.getPublic();
    }
    
    @Override
    public void init(String location)
    {
        File f = new File(location + ".pub");
        if (f.exists())
            try {
                BufferedReader br = new BufferedReader(new FileReader(f));
                String keydata = br.readLine();
                if (keydata != null) {
                    String[] parts = keydata.split(" ");
                    assert parts.length >= 2;
                    type = KeyType.fromString(parts[0]);
                    pubKey = new Buffer(Base64.decode(parts[1])).getPublicKey();
                }
                br.close();
            } catch (IOException e) {
                // let super provide both public & private key
                log.warn("Error reading public key file: {}", e.toString());
            }
        super.init(location);
    }
}
