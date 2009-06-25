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
import java.net.InetAddress;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.net.ssh.transport.HostKeyVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * TODO:
 * 
 * > way from complete, finish by end-of-month
 * 
 * .... once done:
 * 
 * > document
 * 
 * > unit tests
 * 
 */

/**
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public class KnownHosts implements HostKeyVerifier
{
    
    public static String[] guessLocations()
    {
        String kh = System.getProperty("user.home") + File.separator
                + (System.getProperty("os.name").startsWith("Windows") ? "ssh" : ".ssh")
                + File.separator + "known_hosts";
        return new String[] { kh, kh + "2" };
    }
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    
    private final Map<String, List<PublicKey>> entries = new HashMap<String, List<PublicKey>>();
    
    KnownHosts()
    {
        this(guessLocations());
    }
    
    KnownHosts(String[] locations)
    {
        for (String l : locations)
            readIn(l);
    }
    
    public void add(final String host, final PublicKey key)
    {
        List<PublicKey> l = entries.get(host);
        if (l != null)
            l.add(key);
        else
            entries.put(host, new LinkedList<PublicKey>()
            {
                {
                    this.add(key);
                }
            });
    }
    
    private void fromLine(String line)
    {
        String[] parts = line.split(" "); // { host, keytype, key }
        if (parts.length != 3)
            return;
    }
    
    private void readIn(String l)
    {
        try {
            BufferedReader br = new BufferedReader(new FileReader(l));
            String line;
            while ((line = br.readLine()) != null)
                fromLine(line);
        } catch (Exception e) {
            log.error("Error loading {}: {}", e);
        }
    }
    
    public boolean verify(InetAddress host, PublicKey key)
    {
        return false;
    }
    
}

// private static boolean isHashed(String host)
// {
// return host.startsWith("|1|");
// }
