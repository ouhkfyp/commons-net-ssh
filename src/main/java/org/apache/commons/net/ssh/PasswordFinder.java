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
package org.apache.commons.net.ssh;

import java.util.Arrays;
import java.util.Map;

/**
 * On the lines of org.bouncycastle.openssl.PasswordFinder, with an additional retry() method to
 * check if we should retry on failure (should help GUI apps)
 * 
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
public interface PasswordFinder
{
    
    /**
     * A password-protected resource
     * 
     * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
     */
    class Resource
    {
        
        public enum Type
        {
            ACCOUNT, // corresponding detail = "username"
            KEYFILE, // corresponding detail = "file location" e.g. cannonical path
        }
        
        private final Type type;
        private final String detail;
        
        public Resource(Type type, String detail)
        {
            this.type = type;
            this.detail = detail;
        }
        
        @Override
        public boolean equals(Object r2)
        {
            if (r2 instanceof Resource)
                return ((Resource) r2).type == type && ((Resource) r2).detail.equals(detail);
            else
                return false;
        }
        
        public String getInfo()
        {
            return detail;
        }
        
        public Type getType()
        {
            return type;
        }
        
        @Override
        public int hashCode()
        {
            return (type + detail).hashCode();
        }
        
        @Override
        public String toString()
        {
            return "[" + type + "] " + detail;
        }
        
    }
    
    class Util
    {
        public static void blankOut(char[] pass)
        {
            if (pass != null)
                Arrays.fill(pass, ' ');
        }
        
        public static PasswordFinder createOneOff(final char[] password)
        {
            return new PasswordFinder()
            {
                public char[] getPassword(Resource resource)
                {
                    return password;
                }
                
                public boolean retry()
                {
                    return false;
                }
            };
        }
        
        public static PasswordFinder createOneOff(String password)
        {
            try {
                return createOneOff(password.toCharArray());
            } finally {
                password = null;
            }
        }
        
        public static PasswordFinder createResourceBased(final Map<Resource, char[]> passwordMap)
        {
            return new PasswordFinder()
            {
                public char[] getPassword(Resource resource)
                {
                    return passwordMap.get(resource);
                }
                
                public boolean retry()
                {
                    return false;
                }
                
            };
        }
        
    }
    
    char[] getPassword(Resource resource);
    
    boolean retry();
    
}
