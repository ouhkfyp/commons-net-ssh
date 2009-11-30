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
package org.apache.commons.net.ssh.sftp;

import java.util.Set;

import org.apache.commons.net.ssh.xfer.FilePermission;

public class FileMode
{
    
    public static enum Type
    {
        /** block special */
        BLOCK_SPECIAL(0060000),
        /** character special */
        CHAR_SPECIAL(0020000),
        /** FIFO special */
        FIFO_SPECIAL(0010000),
        /** socket special */
        SOCKET_SPECIAL(0140000),
        /** regular */
        REGULAR(0100000),
        /** directory */
        DIRECTORY(0040000),
        /** symbolic link */
        SYMKLINK(0120000),
        /** unknown */
        UNKNOWN(0);
        
        private final int val;
        
        private Type(int val)
        {
            this.val = val;
        }
        
        public static Type fromMask(int mask)
        {
            for (Type t : Type.values())
                if (t.val == mask)
                    return t;
            return UNKNOWN;
        }
        
        public static int toMask(Type t)
        {
            return t.val;
        }
        
    }
    
    private final int mask;
    private final Type type;
    private final Set<FilePermission> perms;
    
    public FileMode(int mask)
    {
        this.mask = mask;
        this.type = Type.fromMask(getTypeMask());
        this.perms = FilePermission.fromMask(getPermissionsMask());
    }
    
    public int getMask()
    {
        return mask;
    }
    
    public int getTypeMask()
    {
        return mask & 0770000;
    }
    
    public int getPermissionsMask()
    {
        return mask & 07777;
    }
    
    public Type getType()
    {
        return type;
    }
    
    public Set<FilePermission> getPermissions()
    {
        return perms;
    }
    
    @Override
    public String toString()
    {
        return "[mask=" + Integer.toOctalString(mask) + "]";
    }
    
}
