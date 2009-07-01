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
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.commons.net.ssh.SSHRuntimeException;
import org.apache.commons.net.ssh.Constants.KeyType;
import org.apache.commons.net.ssh.mac.HMACSHA1;
import org.apache.commons.net.ssh.mac.MAC;
import org.apache.commons.net.ssh.transport.Session.HostKeyVerifier;
import org.apache.log4j.BasicConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KnownHosts implements HostKeyVerifier
{
    
    private static class Entry
    {
        
        final String[] hosts;
        final KeyType type;
        final String sKey;
        
        Entry(String line) throws AssertionError
        {
            String[] parts = line.split(" ");
            assert parts.length == 3;
            hosts = parts[0].split(",");
            type = KeyType.fromString(parts[1]);
            assert type != KeyType.UNKNOWN;
            sKey = parts[2];
        }
        
        boolean appliesTo(Set<String> possibilities)
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
                        return true;
            } else
                for (String host : hosts)
                    if (possibilities.contains(host))
                        return true;
            return false;
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
    
    public static String[] guessLocations()
    {
        String kh = System.getProperty("user.home") + File.separator + ".ssh" + File.separator
                + "known_hosts";
        return new String[] { kh, kh + "2" };
    }
    
    public static void main(String[] args)
    {
        BasicConfigurator.configure();
        KnownHosts kh = new KnownHosts();
        Set<String> possibilities = new HashSet<String>();
        possibilities.add("localhost");
        possibilities.add("127.0.0.1");
        for (Entry e : kh.entries)
            System.out.println(e.appliesTo(possibilities));
    }
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final List<Entry> entries = new LinkedList<Entry>();
    
    KnownHosts()
    {
        this(guessLocations());
    }
    
    KnownHosts(String... locations)
    {
        for (String l : locations)
            try {
                BufferedReader br = new BufferedReader(new FileReader(l));
                String line;
                while ((line = br.readLine()) != null)
                    try {
                        entries.add(new Entry(line));
                    } catch (AssertionError e) {
                        log.warn("unrecognized line: {}", line);
                        continue;
                    }
            } catch (Exception e) {
                log.error("Error loading {}: {}", l, e);
            }
    }
    
    private Set<String> makePossibilities(InetAddress host)
    {
        Set<String> possibilities = new HashSet<String>();
        possibilities.add(host.getHostName());
        possibilities.add(host.getCanonicalHostName());
        possibilities.add(host.getHostAddress());
        return possibilities;
    }
    
    public boolean verify(InetAddress host, PublicKey key)
    {
        KeyType type = KeyType.fromKey(key);
        if (type == KeyType.UNKNOWN)
            return false;
        
        Set<String> possibilities = makePossibilities(host);
        
        for (Entry e : entries)
            if (e.type == type && e.appliesTo(possibilities))
                if (key.equals(e.getKey()))
                    return true;
        return false;
    }
    
}
