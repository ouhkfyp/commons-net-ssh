package org.apache.commons.net.ssh.util;

import org.apache.commons.codec.binary.Base64;
import java.security.PublicKey;

public class HostKeys
{
    
    public static class Entry
    {
        
        private String[] hostnames = null;
        private PublicKey pkey = null;
        
        private Entry(PublicKey pkey, String[] hostnames)
        {
            this.pkey = pkey;
            this.hostnames = hostnames;
        }
        
        public static Entry fromLine(String line)
        {
            String[] fields = line.split(" ");
            assert fields.length == 3;
            
            byte[] keyData = Base64.decodeBase64(fields[2].getBytes());
            
            PublicKey key = null;
            //KeyPair kp = new 
            if (fields[1].equals("ssh-rsa"))
                ;
            else if (fields[1].equals("ssh-dss"))
                ;
            else
                assert false;
            
            return new Entry(key, fields[0].split(","));
        }
    
    }
    

    
}

