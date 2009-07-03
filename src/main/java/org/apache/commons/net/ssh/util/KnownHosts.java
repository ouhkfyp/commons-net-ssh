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
package org.apache.commons.net.ssh.util;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.commons.net.ssh.HostKeyVerifier;
import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.Constants.KeyType;
import org.apache.commons.net.ssh.mac.HMACSHA1;
import org.apache.commons.net.ssh.mac.MAC;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A HostKeyVerifier implementation for OpenSSH-known_hosts-style files
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class KnownHosts implements HostKeyVerifier
{
    
    private static class Entry
    {
        
        private final String[] hosts;
        private final KeyType type;
        private final String sKey;
        
        Entry(String line) throws AssertionError
        {
            String[] parts = line.split(" ");
            assert parts.length == 3;
            hosts = parts[0].split(",");
            type = KeyType.fromString(parts[1]);
            assert type != KeyType.UNKNOWN;
            sKey = parts[2];
        }
        
        String appliesTo(Set<String> possibilities)
        {
            if (hosts[0].startsWith("|1|")) { // hashed
                String[] splitted = hosts[0].split("\\|");
                byte[] salt, host;
                try {
                    salt = Base64.decode(splitted[2]);
                    host = Base64.decode(splitted[3]);
                } catch (IOException e) {
                    throw new SSHRuntimeException(e);
                }
                assert salt.length == 20;
                MAC sha1 = new HMACSHA1();
                sha1.init(salt);
                for (String possi : possibilities)
                    if (BufferUtils.equals(host, sha1.doFinal(possi.getBytes())))
                        return possi;
            } else
                for (String host : hosts)
                    if (possibilities.contains(host))
                        return host;
            return null;
        }
        
        PublicKey getKey()
        {
            byte[] decoded;
            try {
                decoded = Base64.decode(sKey);
            } catch (IOException e) {
                return null;
            }
            return new Buffer(decoded).getPublicKey();
        }
        
    }
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final List<Entry> entries = new LinkedList<Entry>();
    
    public KnownHosts(String... locations)
    {
        for (String loc : locations)
            try {
                BufferedReader br = new BufferedReader(new FileReader(loc));
                String line;
                while ((line = br.readLine()) != null)
                    try {
                        entries.add(new Entry(line));
                    } catch (AssertionError e) {
                        log.debug("{} - unrecognized line: {}", loc, line);
                        continue;
                    }
            } catch (Exception e) {
                log.info("While loading {} - {}", loc, e.toString());
            }
    }
    
    public boolean verify(InetAddress host, PublicKey key)
    {
        KeyType type = KeyType.fromKey(key);
        if (type == KeyType.UNKNOWN)
            return false;
        
        Set<String> possibilities = new HashSet<String>();
        possibilities.add(host.getHostName());
        possibilities.add(host.getCanonicalHostName());
        
        String match;
        for (Entry e : entries)
            if (e.type == type && (match = e.appliesTo(possibilities)) != null)
                if (key.equals(e.getKey())) {
                    log.info("Found a valid match against [{}]", match);
                    return true;
                }
        return false;
    }
    
}
