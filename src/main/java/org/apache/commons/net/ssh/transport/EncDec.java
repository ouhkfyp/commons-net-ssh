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
package org.apache.commons.net.ssh.transport;

import java.io.IOException;

import org.apache.commons.net.ssh.SSHConstants;
import org.apache.commons.net.ssh.SSHException;
import org.apache.commons.net.ssh.cipher.Cipher;
import org.apache.commons.net.ssh.compression.Compression;
import org.apache.commons.net.ssh.mac.MAC;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.BufferUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TODO Give a better name!
 * 
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @author <a href="mailto:shikhar@schmizz.net">Shikhar Bhushan</a>
 */
class EncDec
{
    
    private final Logger log = LoggerFactory.getLogger(getClass());
    private final Transport session;
    
    //
    // SSH packets encoding / decoding support
    //
    private Cipher outCipher;
    private Cipher inCipher;
    private int outCipherSize = 8;
    private int inCipherSize = 8;
    private MAC outMAC;
    private MAC inMAC;
    private byte[] inMACResult;
    private Compression outCompression;
    private Compression inCompression;
    private int seqi; // server -> client seq. no.
    private int seqo; // client -> server seq. no.
    private final Buffer decoderBuffer = new Buffer(); // buffer where as-yet undecoded data lives
    private Buffer uncompressBuffer;
    private int decoderState;
    private int decoderLength;
    
    
    // how many bytes do we need, before a call to decode() can succeed at decoding packet length / the whole packet?
    // see decode()
    private int needed = inCipherSize; 
    
    EncDec(Transport session)
    {
        this.session = session;
    }
    
    /**
     * Decode the incoming buffer and handle packets as needed.
     * <p>
     * Returns advised number of bytes that should be made available in decoderBuffer before the method should be called
     * again.
     * 
     * @throws Exception
     */
    private int decode() throws Exception
    {
        int need;
        // Decoding loop
        for (;;)
            if (decoderState == 0) // Wait for beginning of packet
            {
                // The read position should always be 0 at this point because we have compacted this buffer
                assert decoderBuffer.rpos() == 0;
                // If we have received enough bytes, start processing those
                need = inCipherSize - decoderBuffer.available();
                if (need <= 0)
                {
                    // Decrypt the first bytes
                    if (inCipher != null)
                        inCipher.update(decoderBuffer.array(), 0, inCipherSize);
                    // Read packet length
                    decoderLength = decoderBuffer.getInt();
                    // Check packet length validity
                    if (decoderLength < 5 || decoderLength > 256 * 1024)
                    {
                        log.info("Error decoding packet (invalid length) {}", decoderBuffer.printHex());
                        throw new SSHException(SSHConstants.SSH_DISCONNECT_PROTOCOL_ERROR, "Invalid packet length: "
                                                                                           + decoderLength);
                    }
                    // Ok, that's good, we can go to the next step
                    decoderState = 1;
                } else
                    break;
            } else if (decoderState == 1) // We have received the beginning of the packet
            {
                // The read position should always be 4 at this point
                assert decoderBuffer.rpos() == 4;
                int macSize = inMAC != null ? inMAC.getBlockSize() : 0;
                // Check if the packet has been fully received
                need = decoderLength + macSize - decoderBuffer.available();
                if (need <= 0) 
                {
                    byte[] data = decoderBuffer.array();
                    // Decrypt the remaining of the packet
                    if (inCipher != null)
                        inCipher.update(data, inCipherSize, decoderLength + 4 - inCipherSize);
                    // Check the MAC of the packet
                    if (inMAC != null)
                    {
                        // Update MAC with packet id
                        inMAC.update(seqi);
                        // Update MAC with packet data
                        inMAC.update(data, 0, decoderLength + 4);
                        // Compute MAC result
                        inMAC.doFinal(inMACResult, 0);
                        // Check the computed result with the received mac (just
                        // after the packet data)
                        if (!BufferUtils.equals(inMACResult, 0, data, decoderLength + 4, macSize))
                            throw new SSHException(SSHConstants.SSH_DISCONNECT_MAC_ERROR, "MAC Error");
                    }
                    // Increment incoming packet sequence number
                    seqi++;
                    // Get padding
                    byte pad = decoderBuffer.getByte();
                    Buffer buf;
                    int wpos = decoderBuffer.wpos();
                    // Decompress if needed
                    if (inCompression != null && (session.authed || !inCompression.isDelayed()))
                    {
                        if (uncompressBuffer == null)
                            uncompressBuffer = new Buffer();
                        else
                            uncompressBuffer.clear();
                        decoderBuffer.wpos(decoderBuffer.rpos() + decoderLength - 1 - pad);
                        inCompression.uncompress(decoderBuffer, uncompressBuffer);
                        buf = uncompressBuffer;
                    } else
                    {
                        decoderBuffer.wpos(decoderLength + 4 - pad);
                        buf = decoderBuffer;
                    }
                    if (log.isTraceEnabled())
                        log.trace("Received packet #{}: {}", seqi, buf.printHex());
                    
                    // ----------------------------------------------------- //
                    session.handle(buf); /* process the decoded packet */
                    // ----------------------------------------------------- //
                    
                    // Set ready to handle next packet
                    decoderBuffer.rpos(decoderLength + 4 + macSize);
                    decoderBuffer.wpos(wpos);
                    decoderBuffer.compact();
                    decoderState = 0;
                } else
                    // need more datas
                    break;
            }
        return need;
    }
    
    void gotByte(byte b) throws Exception
    {
        decoderBuffer.putByte(b);
        if (needed == 1)
            needed = decode();
        else
            needed--;
    }
    
    /**
     * Encode a buffer into the SSH protocol. Should be called from a synchronized block.
     * 
     * @param buffer
     *            the buffer to encode
     * @throws IOException
     *             if an exception occurs during the encoding process
     * @return the sequence no. of encoded packet
     */
    int encode(Buffer buffer) throws IOException
    {
        int seq = seqo;
        try
        {
            // Check that the packet has some free space for the header
            if (buffer.rpos() < 5)
            {
                log.warn("Performance cost: when sending a packet, ensure that "
                         + "5 bytes are available in front of the buffer");
                Buffer nb = new Buffer();
                nb.wpos(5);
                nb.putBuffer(buffer);
                buffer = nb;
            }
            // Grab the length of the packet (excluding the 5 header bytes)
            int len = buffer.available();
            int off = buffer.rpos() - 5;
            // Debug log the packet
            if (log.isDebugEnabled())
                log.trace("Sending packet #{}: {}", seqo, buffer.printHex());
            // Compress the packet if needed
            if (outCompression != null && (session.authed || !outCompression.isDelayed()))
            {
                outCompression.compress(buffer);
                len = buffer.available();
            }
            // Compute padding length
            int bsize = outCipherSize;
            int oldLen = len;
            len += 5;
            int pad = -len & bsize - 1;
            if (pad < bsize)
                pad += bsize;
            len = len + pad - 4;
            // Write 5 header bytes
            buffer.wpos(off);
            buffer.putInt(len);
            buffer.putByte((byte) pad);
            // Fill padding
            buffer.wpos(off + oldLen + 5 + pad);
            session.prng.fill(buffer.array(), buffer.wpos() - pad, pad);
            // Compute mac
            if (outMAC != null)
            {
                int macSize = outMAC.getBlockSize();
                int l = buffer.wpos();
                buffer.wpos(l + macSize);
                outMAC.update(seqo);
                outMAC.update(buffer.array(), off, l);
                outMAC.doFinal(buffer.array(), l);
            }
            // Encrypt packet, excluding mac
            if (outCipher != null)
                outCipher.update(buffer.array(), off, len + 4);
            // Increment packet id
            seqo++;
            // Make buffer ready to be read
            buffer.rpos(off);
        } catch (SSHException e)
        {
            throw e;
        } catch (Exception e)
        {
            throw new SSHException(e);
        }
        return seq;
    }
    
    void setClientToServer(Cipher cipher, MAC mac, Compression comp)
    {
        outCipher = cipher;
        outMAC = mac;
        outCompression = comp;
        outCipherSize = cipher.getIVSize();
        if (comp != null)
            outCompression.init(Compression.Type.Deflater, -1);
    }
    
    void setServerToClient(Cipher cipher, MAC mac, Compression comp)
    {
        inCipher = cipher;
        inMAC = mac;
        inCompression = comp;
        inCipherSize = cipher.getIVSize();
        inMACResult = new byte[mac.getBlockSize()];
        if (comp != null)
            inCompression.init(Compression.Type.Inflater, -1);
    }
    
}
