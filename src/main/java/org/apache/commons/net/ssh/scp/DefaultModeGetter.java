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
package org.apache.commons.net.ssh.scp;

import java.io.File;
import java.io.IOException;

/**
 * Default implementation of {@link ModeGetter} that supplies file permissions as {@code "644"},
 * directory permissions as {@code "755"}, and does not supply mtime and atime.
 */
public class DefaultModeGetter implements ModeGetter
{
    
    public long getLastAccessTime(File f)
    {
        // return f.lastModified() / 1000;
        return 0;
    }
    
    public long getLastModifiedTime(File f)
    {
        // return f.lastModified() / 1000;
        return 0;
    }
    
    public String getPermissions(File f) throws IOException
    {
        if (f.isDirectory())
            return "755";
        else if (f.isFile())
            return "644";
        else
            throw new IOException("Unsupported file type: " + f);
    }
    
    public boolean shouldPreserveTimes()
    {
        return false;
    }
    
}
