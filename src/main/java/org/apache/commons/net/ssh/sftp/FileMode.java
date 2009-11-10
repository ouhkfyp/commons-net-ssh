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

public enum FileMode
{
    
    READ(0x00000001), WRITE(0x00000002), APPEND(0x00000004), CREAT(0x00000008), TRUNC(0x00000010), EXCL(0x00000020);
    
    private final int pflag;
    
    private FileMode(int pflag)
    {
        this.pflag = pflag;
    }
    
    public static int toMask(Set<FileMode> modes)
    {
        int mask = 0;
        for (FileMode m : modes)
            mask |= m.pflag;
        return mask;
    }
    
}
