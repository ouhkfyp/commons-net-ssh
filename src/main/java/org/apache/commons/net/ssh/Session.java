package org.apache.commons.net.ssh;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;

import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.BufferUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * Freely borrows code from mina sshd
 */
public class Session
{
    
    /** Session state */
    public enum State
    {
        KEX_EXPECT_KEXINIT, // initial state, right after connection
        KEX_FOLLOWUP,
        KEX_NEWKEYS,
        KEX_DONE,
        AUTH_REQUESTED,
        AUTH_ONGOING,
        AUTH_PENDING,
        RUNNING, // normal operation
        ERROR,
        STOPPED
        // error occured, exception set
    }
    
    /** logger */
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    /** Outgoing data */
    protected BlockingQueue<byte[]> outQ = new SynchronousQueue<byte[]>();
    
    /**
     * The factory manager used to retrieve factories of Ciphers, MACs and other
     * objects
     */
    protected final FactoryManager factoryManager;
    
    /** The pseudo random generator */
    protected final Random random;
    
    /** Lock object for session state */
    protected final Object stateLock = new Object();
    
    /** Map of channels keyed by the identifier */
    protected final Map<Integer, Channel> channels = new ConcurrentHashMap<Integer, Channel>();
    
    /* stop pumping threads? */
    protected volatile boolean stopPumping = false;
    
    protected boolean authed;
    
    //
    // Key exchange support
    //
    protected byte[] sessionID;
    protected String serverVersion;
    public static final String clientVersion = "SSH-2.0-NET-2.0";
    protected String[] serverProposal;
    protected String[] clientProposal;
    protected String[] negotiated; // negotiated algorithms
    protected byte[] I_C; // the payload of the factoryManager's SSH_MSG_KEXINIT
    protected byte[] I_S; // the payload of the server's SSH_MSG_KEXINIT
    protected KeyExchange kex;
    
    //
    // SSH packets encoding / decoding support
    //
    protected Cipher outCipher;
    protected Cipher inCipher;
    protected int outCipherSize = 8;
    protected int inCipherSize = 8;
    protected MAC outMAC;
    protected MAC inMAC;
    protected byte[] inMACResult;
    protected Compression outCompression;
    protected Compression inCompression;
    protected int seqi;
    protected int seqo;
    protected Buffer decoderBuffer = new Buffer();
    protected Buffer uncompressBuffer;
    protected int decoderState;
    protected int decoderLength;
    protected final Object encodeLock = new Object();
    
    private State state = State.KEX_EXPECT_KEXINIT;
    private UserAuth userAuth;
    
    protected Exception ex;
    
    protected InputStream input;
    protected OutputStream output;
    
    /**
     * This thread takes byte[] from outQ and sends it over the output stream for this session.  
     */
    protected final Thread outPump = new Thread() {
        @Override
        public void run()
        {
            while (!stopPumping)
                try
                {
                    output.write(outQ.take());
                } catch (Exception e)
                {
                    if (!stopPumping)
                        setError(e);
                }
        }
    };
    
    /**
     * This thread reads data from the input stream, putting it into
     * decodeBuffer. Packets are decoded and handled.
     */
    protected final Thread inPump = new Thread() {
        @Override
        public void run()
        {
            // see return value of decode()
            int need = inCipherSize;
            while (!stopPumping) {
                try
                {
                    decoderBuffer.putByte((byte) input.read());
                    if (need == 1)
                        need = decode();
                    else
                        need--;
                } catch (Exception e)
                {
                    if (!stopPumping)
                        setError(e);
                }
            }
        }
    };
    
    Session(FactoryManager factoryManager)
    {
        this.factoryManager = factoryManager;
        random = factoryManager.getRandomFactory().create();
        
        inPump.setName("inPump");
        inPump.setDaemon(true);
        
        outPump.setName("outPump");
        outPump.setDaemon(true);
    }
    
    protected void checkHost() throws Exception
    {
        // TODO: check host fingerprint
    }
    
    /**
     * Create a new buffer for the specified SSH packet and reserve the needed
     * space (5 bytes) for the packet header.
     * 
     * @param cmd
     *            the SSH command
     * @return a new buffer ready for write
     */
    public Buffer createBuffer(SSHConstants.Message cmd)
    {
        Buffer buffer = new Buffer();
        buffer.rpos(5);
        buffer.wpos(5);
        buffer.putByte(cmd.toByte());
        return buffer;
    }
    
    /**
     * Create our proposal for SSH negotiation
     * 
     * @param hostKeyTypes
     *            the list of supported host key types
     * @return an array of 10 strings holding this proposal
     */
    protected String[] createProposal(String hostKeyTypes)
    {
        return new String[] { NamedFactory.Utils.getNames(factoryManager.getKeyExchangeFactories()), hostKeyTypes,
                             NamedFactory.Utils.getNames(factoryManager.getCipherFactories()),
                             NamedFactory.Utils.getNames(factoryManager.getCipherFactories()),
                             NamedFactory.Utils.getNames(factoryManager.getMACFactories()),
                             NamedFactory.Utils.getNames(factoryManager.getMACFactories()),
                             NamedFactory.Utils.getNames(factoryManager.getCompressionFactories()),
                             NamedFactory.Utils.getNames(factoryManager.getCompressionFactories()), "", "" };
    }
    
    /**
     * Decode the incoming buffer and handle packets as needed.
     * <p>
     * Returns advised number of bytes that should be made available in
     * decoderBuffer before it should be called again.
     * 
     * @throws Exception
     */
    protected int decode() throws Exception
    {
        int need;
        // Decoding loop
        for (;;)
            if (decoderState == 0) // Wait for beginning of packet
            {
                // The read position should always be 0 at this point because we
                // have compacted this buffer
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
            } else if (decoderState == 1) // We have received the beinning of the packet
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
                    if (inCompression != null && (authed || !inCompression.isDelayed()))
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
                    // Process decoded packet
                    handleMessage(buf);
                    // Set ready to handle next packet
                    decoderBuffer.rpos(decoderLength + 4 + macSize);
                    decoderBuffer.wpos(wpos);
                    decoderBuffer.compact();
                    decoderState = 0;
                } else
                    // need more data
                    break;
            }
        return need;
    }
    
    /**
     * Send a disconnect packet with the given reason and message. Once the
     * packet has been sent, the session will be closed asynchronously.
     * 
     * @param reason
     *            the reason code for this disconnect
     * @param msg
     *            the text message
     * @throws IOException
     *             if an error occured sending the packet
     */
    public void disconnect(int reason, String msg) throws IOException
    {
        log.debug("Sending SSH_MSG_DISCONNECT: reason=[{}], msg=[{}]", reason, msg);
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_DISCONNECT);
        buffer.putInt(reason);
        buffer.putString(msg);
        buffer.putString("");
        writePacket(buffer);
        stop();
    }
    
    /**
     * Read the remote identification from this buffer. If more data is needed,
     * the buffer will be reset to its original state and a <code>null</code>
     * value will be returned. Else the identification string will be returned
     * and the data read will be consumed from the buffer.
     * 
     * @param buffer
     *            the buffer containing the identification string
     * @return the remote identification or <code>null</code> if more data is
     *         needed
     */
    protected String doReadIdentification(Buffer buffer)
    {
        byte[] data = new byte[256];
        for (;;)
        {
            int rpos = buffer.rpos();
            int pos = 0;
            boolean needLf = false;
            for (;;)
            {
                if (buffer.available() == 0)
                {
                    // Need more data, so undo reading and return null
                    buffer.rpos(rpos);
                    return null;
                }
                byte b = buffer.getByte();
                if (b == '\r')
                {
                    needLf = true;
                    continue;
                }
                if (b == '\n')
                    break;
                if (needLf)
                    throw new IllegalStateException("Incorrect identification: bad line ending");
                if (pos >= data.length)
                    throw new IllegalStateException("Incorrect identification: line too long");
                data[pos++] = b;
            }
            String str = new String(data, 0, pos);
            if (str.startsWith("SSH-"))
                return str;
            if (buffer.rpos() > 16 * 1024)
                throw new IllegalStateException("Incorrect identification: too many header lines");
        }
    }
    
    /**
     * Encode a buffer into the SSH protocol. This method need to be called into
     * a synchronized block around encodeLock
     * 
     * @param buffer
     *            the buffer to encode
     * @throws IOException
     *             if an exception occurs during the encoding process
     */
    private void encode(Buffer buffer) throws IOException
    {
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
            if (outCompression != null && (authed || !outCompression.isDelayed()))
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
            random.fill(buffer.array(), buffer.wpos() - pad, pad);
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
    }
    
    /**
     * Retrieve the factory manager
     * 
     * @return the factory manager for this session
     */
    public FactoryManager getFactoryManager()
    {
        return factoryManager;
    }
    
    protected void extractProposal(Buffer buffer) throws Exception
    {
        serverProposal = new String[SSHConstants.PROPOSAL_MAX];
        I_S = extractProposal(buffer, serverProposal);
    }
    
    /**
     * Receive the remote key exchange init message. The packet data is returned
     * for later use.
     * 
     * @param buffer
     *            the buffer containing the key exchange init packet
     * @param proposal
     *            the remote proposal to fill
     * @return the packet data
     */
    protected byte[] extractProposal(Buffer buffer, String[] proposal)
    {
        // Recreate the packet payload which will be needed at a later time
        byte[] d = buffer.array();
        byte[] data = new byte[buffer.available() + 1];
        data[0] = SSHConstants.Message.SSH_MSG_KEXINIT.toByte();
        System.arraycopy(d, buffer.rpos(), data, 1, data.length - 1);
        // Skip 16 bytes of random data
        buffer.rpos(buffer.rpos() + 16);
        // Read proposal
        for (int i = 0; i < proposal.length; i++)
            proposal[i] = buffer.getString();
        // Skip 5 bytes
        buffer.getByte();
        buffer.getInt();
        // Return data
        return data;
    }
    
    protected void handleMessage(Buffer buffer) throws Exception
    {
        SSHConstants.Message cmd = buffer.getCommand();
        log.debug("Received packet {}", cmd);
        switch (cmd)
        {
            case SSH_MSG_DISCONNECT:
            {
                int code = buffer.getInt();
                String msg = buffer.getString();
                log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, msg);
                stop();
                break;
            }
            case SSH_MSG_UNIMPLEMENTED:
            {
                int code = buffer.getInt();
                log.info("Received SSH_MSG_UNIMPLEMENTED #{}", code);
                break;
            }
            case SSH_MSG_DEBUG:
            {
                boolean display = buffer.getBoolean();
                String msg = buffer.getString();
                log.info("Received SSH_MSG_DEBUG (display={}) '{}'", display, msg);
                break;
            }
            case SSH_MSG_IGNORE:
                log.info("Received SSH_MSG_IGNORE");
                break;
            default:
                switch (state)
                {
                    case KEX_EXPECT_KEXINIT:
                        if (cmd != SSHConstants.Message.SSH_MSG_KEXINIT)
                        {
                            log.error("Ignoring command " + cmd + " while waiting for "
                                      + SSHConstants.Message.SSH_MSG_KEXINIT);
                            break;
                        }
                        log.info("Received SSH_MSG_KEXINIT");
                        extractProposal(buffer);
                        negotiate();
                        kex = NamedFactory.Utils.create(factoryManager.getKeyExchangeFactories(),
                                                        negotiated[SSHConstants.PROPOSAL_KEX_ALGS]);
                        kex.init(this, serverVersion.getBytes(), Session.clientVersion.getBytes(), I_S, I_C);
                        setState(State.KEX_FOLLOWUP);
                        break;
                    case KEX_FOLLOWUP:
                        log.info("Received KEX followup data");
                        buffer.rpos(buffer.rpos() - 1);
                        if (kex.next(buffer))
                        {
                            checkHost();
                            sendNewKeys();
                            setState(State.KEX_NEWKEYS);
                        }
                        break;
                    case KEX_NEWKEYS:
                        if (cmd != SSHConstants.Message.SSH_MSG_NEWKEYS)
                        {
                            disconnect(SSHConstants.SSH_DISCONNECT_PROTOCOL_ERROR,
                                       "Protocol error: expected packet SSH_MSG_NEWKEYS, got " + cmd);
                            return;
                        }
                        log.info("Received SSH_MSG_NEWKEYS");
                        receivedNewKeys();
                        setState(State.KEX_DONE);
                        break;
                    case AUTH_REQUESTED:
                        if (cmd != SSHConstants.Message.SSH_MSG_SERVICE_ACCEPT)
                        {
                            disconnect(SSHConstants.SSH_DISCONNECT_PROTOCOL_ERROR,
                                       "Protocol error: expected packet SSH_MSG_SERVICE_ACCEPT, got " + cmd);
                            return;
                        }
                        setState(State.AUTH_PENDING);
                        break;
                    case AUTH_PENDING:
                        // We're waiting for the client to send an
                        // authentication request
                        // TODO: handle unexpected incoming packets
                        break;
                    case AUTH_ONGOING:
                        if (userAuth == null)
                        {
                            throw new IllegalStateException("State is AUTH_ONGOING, received packet, but no user auth pending!!");
                        }
                        buffer.rpos(buffer.rpos() - 1);
                        switch (userAuth.next(buffer))
                        {
                            case Success:
                                // authFuture.setAuthed(true);
                                authed = true;
                                setState(State.RUNNING);
                                break;
                            case Failure:
                                // authFuture.setAuthed(false);
                                userAuth = null;
                                setState(State.AUTH_PENDING);
                                break;
                            case Continued:
                                break;
                        }
                        break;
                    case RUNNING:
                        switch (cmd) {
                            case SSH_MSG_KEXINIT:
                                setState(State.KEX_FOLLOWUP);
//                            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
//                                channelOpenConfirmation(buffer);
//                                break;
//                            case SSH_MSG_CHANNEL_OPEN_FAILURE:
//                                channelOpenFailure(buffer);
//                                break;
//                            case SSH_MSG_CHANNEL_REQUEST:
//                                channelRequest(buffer);
//                                break;
//                            case SSH_MSG_CHANNEL_DATA:
//                                channelData(buffer);
//                                break;
//                            case SSH_MSG_CHANNEL_EXTENDED_DATA:
//                                channelExtendedData(buffer);
//                                break;
//                            case SSH_MSG_CHANNEL_FAILURE:
//                                channelFailure(buffer);
//                                break;
//                            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
//                                channelWindowAdjust(buffer);
//                                break;
//                            case SSH_MSG_CHANNEL_EOF:
//                                channelEof(buffer);
//                                break;
//                            case SSH_MSG_CHANNEL_CLOSE:
//                                channelClose(buffer);
//                                break;
//                                // TODO: handle other requests
                        }
                        break;
                }
                }
        }
    
    protected void init() throws Exception
    {
        log.info("Client version string: {}", Session.clientVersion);
        output.write((Session.clientVersion + "\r\n").getBytes());
        
        // read server ident string
        Buffer buf = new Buffer();
        while (!readIdentification(buf))
            buf.putByte((byte) input.read());
        
        outPump.start();
        sendKexInit();
        inPump.start();
        
        waitFor(State.KEX_DONE);
        
        sendAuthRequest();
        waitFor(State.AUTH_PENDING);
    }
    
    public boolean isAuthenticated()
    {
        return authed;
    }
    
    public boolean isRunning()
    {
        return state != State.STOPPED && state != State.ERROR;
    }
    
    /**
     * Compute the negotiated proposals by merging the client and server
     * proposal. The negocatiated proposal will be stored in the
     * {@link #negotiated} property.
     */
    protected void negotiate()
    {
        String[] guess = new String[SSHConstants.PROPOSAL_MAX];
        for (int i = 0; i < SSHConstants.PROPOSAL_MAX; i++)
        {
            String[] c = clientProposal[i].split(",");
            String[] s = serverProposal[i].split(",");
            for (String ci : c)
            {
                for (String si : s)
                    if (ci.equals(si))
                    {
                        guess[i] = ci;
                        break;
                    }
                if (guess[i] != null)
                    break;
            }
            if (guess[i] == null && i != SSHConstants.PROPOSAL_LANG_CTOS && i != SSHConstants.PROPOSAL_LANG_STOC)
                throw new IllegalStateException("Unable to negotiate");
        }
        negotiated = guess;
    }
    
    /**
     * Send an unimplemented packet. This packet should contain the sequence id
     * of the unsupported packet: this number is assumed to be the last packet
     * received.
     * 
     * @throws IOException
     *             if an error occured sending the packet
     */
    protected void notImplemented() throws IOException
    {
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_UNIMPLEMENTED);
        buffer.putInt(seqi - 1);
        writePacket(buffer);
    }
    
    protected boolean readIdentification(Buffer buffer) throws IOException
    {
        if ((serverVersion = doReadIdentification(buffer)) == null)
            return false;
        log.info("Server version string: {}", serverVersion);
        if (!serverVersion.startsWith("SSH-2.0-"))
            throw new SSHException(SSHConstants.SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                                   "Unsupported protocol version: " + serverVersion);
        return true;
    }
    
    /**
     * Put new keys into use. This method will intialize the ciphers, digests,
     * MACs and compression according to the negotiated server and client
     * proposals.
     * 
     * @throws Exception
     *             if an error occurs
     */
    protected void receivedNewKeys() throws Exception
    {
        byte[] IVc2s;
        byte[] IVs2c;
        byte[] Ec2s;
        byte[] Es2c;
        byte[] MACc2s;
        byte[] MACs2c;
        byte[] K = kex.getK();
        byte[] H = kex.getH();
        Digest hash = kex.getHash();
        Cipher s2ccipher;
        Cipher c2scipher;
        MAC s2cmac;
        MAC c2smac;
        Compression s2ccomp;
        Compression c2scomp;
        
        if (sessionID == null)
        {
            sessionID = new byte[H.length];
            System.arraycopy(H, 0, sessionID, 0, H.length);
        }
        
        Buffer buffer = new Buffer();
        buffer.putMPInt(K);
        buffer.putRawBytes(H);
        buffer.putByte((byte) 0x41);
        buffer.putRawBytes(sessionID);
        int pos = buffer.available();
        byte[] buf = buffer.array();
        hash.update(buf, 0, pos);
        IVc2s = hash.digest();
        
        int j = pos - sessionID.length - 1;
        
        buf[j]++;
        hash.update(buf, 0, pos);
        IVs2c = hash.digest();
        
        buf[j]++;
        hash.update(buf, 0, pos);
        Ec2s = hash.digest();
        
        buf[j]++;
        hash.update(buf, 0, pos);
        Es2c = hash.digest();
        
        buf[j]++;
        hash.update(buf, 0, pos);
        MACc2s = hash.digest();
        
        buf[j]++;
        hash.update(buf, 0, pos);
        MACs2c = hash.digest();
        
        s2ccipher = NamedFactory.Utils.create(factoryManager.getCipherFactories(),
                                              negotiated[SSHConstants.PROPOSAL_ENC_ALGS_STOC]);
        Es2c = resizeKey(Es2c, s2ccipher.getBlockSize(), hash, K, H);
        s2ccipher.init(Cipher.Mode.Decrypt, Es2c, IVs2c);
        
        s2cmac = NamedFactory.Utils.create(factoryManager.getMACFactories(),
                                           negotiated[SSHConstants.PROPOSAL_MAC_ALGS_STOC]);
        s2cmac.init(MACs2c);
        
        c2scipher = NamedFactory.Utils.create(factoryManager.getCipherFactories(),
                                              negotiated[SSHConstants.PROPOSAL_ENC_ALGS_CTOS]);
        Ec2s = resizeKey(Ec2s, c2scipher.getBlockSize(), hash, K, H);
        c2scipher.init(Cipher.Mode.Encrypt, Ec2s, IVc2s);
        
        c2smac = NamedFactory.Utils.create(factoryManager.getMACFactories(),
                                           negotiated[SSHConstants.PROPOSAL_MAC_ALGS_CTOS]);
        c2smac.init(MACc2s);
        
        s2ccomp = NamedFactory.Utils.create(factoryManager.getCompressionFactories(),
                                            negotiated[SSHConstants.PROPOSAL_COMP_ALGS_STOC]);
        c2scomp = NamedFactory.Utils.create(factoryManager.getCompressionFactories(),
                                            negotiated[SSHConstants.PROPOSAL_COMP_ALGS_CTOS]);
        
        outCipher = c2scipher;
        outMAC = c2smac;
        outCompression = c2scomp;
        inCipher = s2ccipher;
        inMAC = s2cmac;
        inCompression = s2ccomp;
        
        outCipherSize = outCipher.getIVSize();
        if (outCompression != null)
            outCompression.init(Compression.Type.Deflater, -1);
        inCipherSize = inCipher.getIVSize();
        inMACResult = new byte[inMAC.getBlockSize()];
        if (inCompression != null)
            inCompression.init(Compression.Type.Inflater, -1);
    }
    
    /**
     * Private method used while putting new keys into use that will resize the
     * key used to initialize the cipher to the needed length.
     * 
     * @param E
     *            the key to resize
     * @param blockSize
     *            the cipher block size
     * @param hash
     *            the hash algorithm
     * @param K
     *            the key exchange K parameter
     * @param H
     *            the key exchange H parameter
     * @return the resized key
     * @throws Exception
     *             if a problem occur while resizing the key
     */
    private byte[] resizeKey(byte[] E, int blockSize, Digest hash, byte[] K, byte[] H) throws Exception
    {
        while (blockSize > E.length)
        {
            Buffer buffer = new Buffer();
            buffer.putMPInt(K);
            buffer.putRawBytes(H);
            buffer.putRawBytes(E);
            hash.update(buffer.array(), 0, buffer.available());
            byte[] foo = hash.digest();
            byte[] bar = new byte[E.length + foo.length];
            System.arraycopy(E, 0, bar, 0, E.length);
            System.arraycopy(foo, 0, bar, E.length, foo.length);
            E = bar;
        }
        return E;
    }
    
    protected void sendAuthRequest() throws IOException
    {
        log.info("Sending SSH_MSG_SERVICE_REQUEST for ssh-userauth");
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_SERVICE_REQUEST);
        buffer.putString("ssh-userauth");
        writePacket(buffer);
        setState(State.AUTH_REQUESTED);
    }
    
    protected void sendKexInit() throws IOException
    {
        clientProposal = createProposal(KeyPairProvider.SSH_RSA + "," + KeyPairProvider.SSH_DSS);
        I_C = sendKexInit(clientProposal);
    }
    
    /**
     * Send the key exchange initialization packet.
     * 
     * @param proposal
     *            our proposal for key exchange negociation
     * @return the sent packet which must be kept for later use
     * @throws IOException
     *             if an error occured sending the packet
     */
    protected byte[] sendKexInit(String[] proposal) throws IOException
    {
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_KEXINIT);
        int p = buffer.wpos();
        buffer.wpos(p + 16);
        random.fill(buffer.array(), p, 16);
        for (String s : proposal)
            buffer.putString(s);
        buffer.putByte((byte) 0);
        buffer.putInt(0);
        byte[] data = buffer.getCompactData();
        log.info("Sending SSH_MSG_KEXINIT");
        writePacket(buffer);
        return data;
    }
    
    /**
     * Send a message to put new keys into use.
     * 
     * @throws IOException
     *             if an error occurs sending the message
     */
    protected void sendNewKeys() throws IOException
    {
        log.info("Send SSH_MSG_NEWKEYS");
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_NEWKEYS);
        writePacket(buffer);
    }
    
    /**
     * Used by inPump and outPump to notify of an error, since it would
     * otherwise escape unnoticed
     * 
     * @param e
     *            Exception
     */
    protected void setError(Exception e)
    {
        ex = e;
        log.error("A pumping thread reported {}", e.toString());
        
        // TODO: notify open channels

        /*
         * will result in ex being thrown in any thread that was waiting for
         * state change; see waitFor()
         */
        setState(State.ERROR);
        
        stopPumping(); // stop inPump and outPump
    }
    
    public void setInputStream(InputStream input)
    {
        this.input = input;
    }
    
    public void setOutputStream(OutputStream output)
    {
        this.output = output;
    }
    
    protected void setState(State newState)
    {
        log.debug("Changing state from {} -> {}", state, newState);
        synchronized (stateLock)
        {
            state = newState;
            stateLock.notifyAll();
        }
    }
    
    private void stop()
    {
        setState(State.STOPPED); // will wakeup any thread that was waiting for state change; see waitFor()
        stopPumping(); // stop inPump and outPump
    }
    
    protected void stopPumping()
    {
        stopPumping = true;
    }
    
    /**
     * Block for specified state.
     * 
     * @param s
     *            State
     * @throws Exception
     *             in case of error event while waiting
     */
    protected void waitFor(State s) throws Exception
    {
        synchronized (stateLock)
        {
            while (state != s && state != State.ERROR)
                try
                {
                    stateLock.wait(0);
                } catch (InterruptedException e)
                {
                    throw e;
                }
        }
        log.debug("Woke up to {}", state.toString());
        if (state == State.ERROR)
            throw ex;
    }
    
    /**
     * Encode the payload as an SSH packet and send it over the session.
     * 
     * @param payload
     * @throws IOException
     */
    public void writePacket(Buffer payload) throws IOException
    {
        /*
         * Synchronize all write requests as needed by the encoding algorithm
         * and also queue the write request in this synchronized block to ensure
         * packets are sent in the correct order
         */
        synchronized (encodeLock)
        {
            encode(payload);
            byte[] data = payload.getCompactData();
            try
            {
                while (!outQ.offer(data, 1L, TimeUnit.SECONDS))
                    if (!outPump.isAlive())
                        throw new IOException("Output pumping thread is dead");
            } catch (InterruptedException e)
            {
                InterruptedIOException ioe = new InterruptedIOException();
                ioe.initCause(e);
                throw ioe;
            }
        }
    }
    
}
