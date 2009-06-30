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
package org.apache.commons.net.ssh.compression;

import java.io.IOException;

import org.apache.commons.net.ssh.NamedFactory;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.Constants.DisconnectReason;
import org.apache.commons.net.ssh.util.Buffer;

import com.jcraft.jzlib.JZlib;
import com.jcraft.jzlib.ZStream;

/**
 * ZLib based Compression.
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CompressionZlib implements Compression
{
    
    /**
     * Named factory for the ZLib Compression.
     */
    public static class Factory implements NamedFactory<Compression>
    {
        public Compression create()
        {
            return new CompressionZlib();
        }
        
        public String getName()
        {
            return "zlib";
        }
    }
    
    static private final int BUF_SIZE = 4096;
    
    private ZStream stream;
    private final byte[] tmpbuf = new byte[BUF_SIZE];
    
    /**
     * Create a new instance of a ZLib base compression
     */
    public CompressionZlib()
    {
    }
    
    public void compress(Buffer buffer) throws IOException
    {
        stream.next_in = buffer.array();
        stream.next_in_index = buffer.rpos();
        stream.avail_in = buffer.available();
        buffer.wpos(buffer.rpos());
        do {
            stream.next_out = tmpbuf;
            stream.next_out_index = 0;
            stream.avail_out = BUF_SIZE;
            int status = stream.deflate(JZlib.Z_PARTIAL_FLUSH);
            switch (status)
            {
            case JZlib.Z_OK:
                buffer.putRawBytes(tmpbuf, 0, BUF_SIZE - stream.avail_out);
                break;
            default:
                throw new SSHException(DisconnectReason.COMPRESSION_ERROR,
                        "compress: deflate returned " + status);
            }
        } while (stream.avail_out == 0);
    }
    
    public void init(Type type, int level)
    {
        stream = new ZStream();
        if (type == Type.Deflater)
            stream.deflateInit(level);
        else
            stream.inflateInit();
    }
    
    public boolean isDelayed()
    {
        return false;
    }
    
    public void uncompress(Buffer from, Buffer to) throws IOException
    {
        stream.next_in = from.array();
        stream.next_in_index = from.rpos();
        stream.avail_in = from.available();
        
        while (true) {
            stream.next_out = tmpbuf;
            stream.next_out_index = 0;
            stream.avail_out = BUF_SIZE;
            int status = stream.inflate(JZlib.Z_PARTIAL_FLUSH);
            switch (status)
            {
            case JZlib.Z_OK:
                to.putRawBytes(tmpbuf, 0, BUF_SIZE - stream.avail_out);
                break;
            case JZlib.Z_BUF_ERROR:
                return;
            default:
                throw new SSHException(DisconnectReason.COMPRESSION_ERROR,
                        "uncompress: inflate returned " + status);
            }
        }
    }
    
}
