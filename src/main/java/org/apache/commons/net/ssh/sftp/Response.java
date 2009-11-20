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

public class Response extends Packet
{
    
    public static enum StatusCode
    {
        UNKNOWN(-1),
        OK(0),
        EOF(1),
        NO_SUCH_FILE(2),
        PERMISSION_DENIED(3),
        FAILURE(4),
        BAD_MESSAGE(5),
        NO_CONNECTION(6),
        CONNECITON_LOST(7),
        OP_UNSUPPORTED(8);
        
        private final int code;
        
        public static StatusCode fromInt(int code)
        {
            for (StatusCode s : StatusCode.values())
                if (s.code == code)
                    return s;
            return UNKNOWN;
        }
        
        private StatusCode(int code)
        {
            this.code = code;
        }
        
    }
    
    private final PacketType type;
    private final long reqID;
    
    public Response(Packet pk)
    {
        super(pk);
        this.type = readType();
        this.reqID = readLong();
    }
    
    public long getRequestID()
    {
        return reqID;
    }
    
    public PacketType getType()
    {
        return type;
    }
    
    public StatusCode readStatusCode()
    {
        return StatusCode.fromInt(readInt());
    }
    
    public void ensurePacket(PacketType pt) throws SFTPException
    {
        
    }
    
    public void ensureOK() throws SFTPException
    {
        ensureStatus(StatusCode.OK);
    }
    
    public void ensureStatus(StatusCode acceptable) throws SFTPException
    {
        if (getType() == PacketType.STATUS)
        {
            StatusCode sc = readStatusCode();
            if (sc != acceptable)
                throw new SFTPException(sc, readString());
        }
    }
    
}
