package org.apache.commons.net.ssh;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.SynchronousQueue;

import org.apache.commons.net.SocketClient;
import org.apache.commons.net.ssh.util.Buffer;
import org.apache.commons.net.ssh.util.BufferUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * AuthHandler
 * MessageHandler 
 */

/*
 * Freely borrows code from mina sshd
 */
public class Session extends SocketClient implements Runnable
{
    public enum State {
        ReceiveKexInit, Kex, ReceiveNewKeys, AuthRequestSent, WaitForAuth, UserAuth, Running, Unknown
    }
    
    /** logger */
    protected final Logger log = LoggerFactory.getLogger(getClass());
    
    public static final int DEFAULT_PORT = 22;
    
    BlockingQueue<byte[]> outQ = new SynchronousQueue<byte[]>();
    
    /**
     * The factory manager used to retrieve factories of Ciphers, MACs and other
     * objects
     */
    protected final FactoryManager factoryManager;
    
    /** The pseudo random generator */
    protected final Random random;
    
    /** Lock object for this session state */
    protected final Object lock = new Object();
    
    /** Boolean indicating if this session has been authenticated or not */
    protected boolean authed;
    
    /** Map of channels keyed by the identifier */
    protected final Map<Integer, Channel> channels =
            new ConcurrentHashMap<Integer, Channel>();
    
    /** Next channel identifier */
    protected int nextChannelID;
    
    private volatile boolean done = false;
    
    //
    // Key exchange support
    //
    protected byte[] sessionId;
    protected String serverVersion;
    protected String clientVersion;
    protected String[] serverProposal;
    protected String[] clientProposal;
    protected String[] negotiated;
    protected byte[] I_C; // the payload of the client's SSH_MSG_KEXINIT
    protected byte[] I_S; // the payload of the factoryManager's SSH_MSG_KEXINIT
    protected KeyExchange kex;
    
    //
    // SSH packets encoding / decoding support
    //
    protected Cipher outCipher;
    protected Cipher inCipher;
    protected int outCipherSize = 8;
    protected int inCipherSize = 8;
    protected MAC outMac;
    protected MAC inMac;
    protected byte[] inMacResult;
    protected Compression outCompression;
    protected Compression inCompression;
    protected int seqi;
    protected int seqo;
    protected Buffer decoderBuffer = new Buffer();
    protected Buffer uncompressBuffer;
    protected int decoderState;
    protected int decoderLength;
    protected final Object encodeLock = new Object();
    // protected final Object decodeLock = new Object();
    // -- not needed, since we just have one thread decoding data as it arrives (this one)
    
    private State state = State.ReceiveKexInit;
    private UserAuth userAuth;
    
    Session(FactoryManager factoryManager)
    {
        super();
        setDefaultPort(DEFAULT_PORT);
        
        this.factoryManager = factoryManager;
        this.random = factoryManager.getRandomFactory().create();
    }
    
    /**
     * Close a channel due to a close packet received
     *
     * @param buffer the buffer containing the packet
     * @throws Exception if an error occurs
     */
    protected void channelClose(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.handleClose();
        channelForget(channel);
    }
    
    /**
     * Process incoming data on a channel
     *
     * @param buffer the buffer containing the data
     * @throws Exception if an error occurs
     */
    protected void channelData(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.handleData(buffer);
    }
    
    /**
     * Process end of file on a channel
     *
     * @param buffer the buffer containing the packet
     * @throws Exception if an error occurs
     */
    protected void channelEOF(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.handleEOF();
    }
    
    /**
     * Process incoming extended data on a channel
     *
     * @param buffer the buffer containing the data
     * @throws Exception if an error occurs
     */
    protected void channelExtendedData(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.handleExtendedData(buffer);
    }
    
    /**
     * Process a failure on a channel
     *
     * @param buffer the buffer containing the packet
     * @throws Exception if an error occurs
     */
    protected void channelFailure(Buffer buffer) throws Exception {
        Channel channel = getChannel(buffer);
        channel.handleFailure();
    }
    
    /**
     *
     * @param channel
     */
    public void channelForget(Channel channel) {
        channels.remove(channel.getID());
    }
    
    /**
     * Service a request on a channel
     *
     * @param buffer the buffer containing the request
     * @throws Exception if an error occurs
     */
    protected void channelRequest(Buffer buffer) throws IOException {
        Channel channel = getChannel(buffer);
        channel.handleRequest(buffer);
    }
    
    /**
     * Process a window adjust packet on a channel
     *
     * @param buffer the buffer containing the window adjustement parameters
     * @throws Exception if an error occurs
     */
    protected void channelWindowAdjust(Buffer buffer) throws Exception {
        try {
            Channel channel = getChannel(buffer);
            channel.handleWindowAdjust(buffer);
        } catch (SSHException e) {
            log.info(e.getMessage());
        }
    }
    
    /**
     * Create a new buffer for the specified SSH packet and reserve the needed space
     * (5 bytes) for the packet header.
     *
     * @param cmd the SSH command
     * @return a new buffer ready for write
     */
    public Buffer createBuffer(SSHConstants.Message cmd) {
        Buffer buffer = new Buffer();
        buffer.rpos(5);
        buffer.wpos(5);
        buffer.putByte(cmd.toByte());
        return buffer;
    }

    /**
     * Create our proposal for SSH negotiation
     *
     * @param hostKeyTypes the list of supported host key types
     * @return an array of 10 strings holding this proposal
     */
    protected String[] createProposal(String hostKeyTypes) {
        return new String[] {
                NamedFactory.Utils.getNames(factoryManager.getKeyExchangeFactories()),
                hostKeyTypes,
                NamedFactory.Utils.getNames(factoryManager.getCipherFactories()),
                NamedFactory.Utils.getNames(factoryManager.getCipherFactories()),
                NamedFactory.Utils.getNames(factoryManager.getMACFactories()),
                NamedFactory.Utils.getNames(factoryManager.getMACFactories()),
                NamedFactory.Utils.getNames(factoryManager.getCompressionFactories()),
                NamedFactory.Utils.getNames(factoryManager.getCompressionFactories()),
                "",
                ""
        };
    }
    
    /**
     * Decode the incoming buffer and handle packets as needed.
     * 
     * @throws Exception
     */
    protected void decode() throws Exception
    {
        // Decoding loop
        for (;;)
        {
            // Wait for beginning of packet
            if (decoderState == 0)
            {
                // The read position should always be 0 at this point because we
                // have compacted this buffer
                assert decoderBuffer.rpos() == 0;
                // If we have received enough bytes, start processing those
                if (decoderBuffer.available() > inCipherSize)
                {
                    // Decrypt the first bytes
                    if (inCipher != null)
                    {
                        inCipher.update(
                                        decoderBuffer.array(), 0, inCipherSize);
                    }
                    // Read packet length
                    decoderLength = decoderBuffer.getInt();
                    // Check packet length validity
                    if (decoderLength < 5 || decoderLength > (256 * 1024))
                    {
                        log.info(
                                 "Error decoding packet (invalid length) {}",
                                 decoderBuffer.printHex());
                        throw new SSHException(
                                               SSHConstants.SSH2_DISCONNECT_PROTOCOL_ERROR,
                                               "Invalid packet length: "
                                                       + decoderLength);
                    }
                    // Ok, that's good, we can go to the next step
                    decoderState = 1;
                } else
                {
                    // need more data
                    break;
                }
                // We have received the beinning of the packet
            } else if (decoderState == 1)
            {
                // The read position should always be 4 at this point
                assert decoderBuffer.rpos() == 4;
                int macSize = inMac != null ? inMac.getBlockSize() : 0;
                // Check if the packet has been fully received
                if (decoderBuffer.available() >= decoderLength + macSize)
                {
                    byte[] data = decoderBuffer.array();
                    // Decrypt the remaining of the packet
                    if (inCipher != null)
                    {
                        inCipher.update(
                                        data, inCipherSize, decoderLength + 4
                                                            - inCipherSize);
                    }
                    // Check the mac of the packet
                    if (inMac != null)
                    {
                        // Update mac with packet id
                        inMac.update(seqi);
                        // Update mac with packet data
                        inMac.update(
                                     data, 0, decoderLength + 4);
                        // Compute mac result
                        inMac.doFinal(
                                      inMacResult, 0);
                        // Check the computed result with the received mac (just
                        // after the packet data)
                        if (!BufferUtils.equals(
                                                inMacResult, 0, data,
                                                decoderLength + 4, macSize))
                        {
                            throw new SSHException(
                                                   SSHConstants.SSH2_DISCONNECT_MAC_ERROR,
                                                   "MAC Error");
                        }
                    }
                    // Increment incoming packet sequence number
                    seqi++;
                    // Get padding
                    byte pad = decoderBuffer.getByte();
                    Buffer buf;
                    int wpos = decoderBuffer.wpos();
                    // Decompress if needed
                    if (inCompression != null
                        && (authed || !inCompression.isDelayed()))
                    {
                        if (uncompressBuffer == null)
                        {
                            uncompressBuffer = new Buffer();
                        } else
                        {
                            uncompressBuffer.clear();
                        }
                        decoderBuffer.wpos(decoderBuffer.rpos() + decoderLength
                                           - 1 - pad);
                        inCompression.uncompress(
                                                 decoderBuffer,
                                                 uncompressBuffer);
                        buf = uncompressBuffer;
                    } else
                    {
                        decoderBuffer.wpos(decoderLength + 4 - pad);
                        buf = decoderBuffer;
                    }
                    if (log.isTraceEnabled())
                    {
                        log.trace(
                                  "Received packet #{}: {}", seqi,
                                  buf.printHex());
                    }
                    // Process decoded packet
                    handleMessage(buf);
                    // Set ready to handle next packet
                    decoderBuffer.rpos(decoderLength + 4 + macSize);
                    decoderBuffer.wpos(wpos);
                    decoderBuffer.compact();
                    decoderState = 0;
                } else
                {
                    // need more data
                    break;
                }
            }
        }
    }    
    
    /**
     * Read the remote identification from this buffer.
     * If more data is needed, the buffer will be reset to its original state
     * and a <code>null</code> value will be returned.  Else the identification
     * string will be returned and the data read will be consumed from the buffer.
     *
     * @param buffer the buffer containing the identification string
     * @return the remote identification or <code>null</code> if more data is needed
     */
    protected String doReadIdentification(Buffer buffer) {
        byte[] data = new byte[256];
        for (;;) {
            int rpos = buffer.rpos();
            int pos = 0;
            boolean needLf = false;
            for (;;) {
                if (buffer.available() == 0) {
                    // Need more data, so undo reading and return null
                    buffer.rpos(rpos);
                    return null;
                }
                byte b = buffer.getByte();
                if (b == '\r') {
                    needLf = true;
                    continue;
                }
                if (b == '\n') {
                    break;
                }
                if (needLf) {
                    throw new IllegalStateException("Incorrect identification: bad line ending");
                }
                if (pos >= data.length) {
                    throw new IllegalStateException("Incorrect identification: line too long");
                }
                data[pos++] = b;
            }
            String str = new String(data, 0, pos);
            if (str.startsWith("SSH-")) {
                return str;
            }
            if (buffer.rpos() > 16 * 1024) {
                throw new IllegalStateException("Incorrect identification: too many header lines");
            }
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
                log
                   .warn("Performance cost: when sending a packet, ensure that "
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
            {
                log.trace(
                          "Sending packet #{}: {}", seqo, buffer.printHex());
            }
            // Compress the packet if needed
            if (outCompression != null
                && (authed || !outCompression.isDelayed()))
            {
                outCompression.compress(buffer);
                len = buffer.available();
            }
            // Compute padding length
            int bsize = outCipherSize;
            int oldLen = len;
            len += 5;
            int pad = (-len) & (bsize - 1);
            if (pad < bsize)
            {
                pad += bsize;
            }
            len = len + pad - 4;
            // Write 5 header bytes
            buffer.wpos(off);
            buffer.putInt(len);
            buffer.putByte((byte) pad);
            // Fill padding
            buffer.wpos(off + oldLen + 5 + pad);
            random.fill(
                        buffer.array(), buffer.wpos() - pad, pad);
            // Compute mac
            if (outMac != null)
            {
                int macSize = outMac.getBlockSize();
                int l = buffer.wpos();
                buffer.wpos(l + macSize);
                outMac.update(seqo);
                outMac.update(
                              buffer.array(), off, l);
                outMac.doFinal(
                               buffer.array(), l);
            }
            // Encrypt packet, excluding mac
            if (outCipher != null)
            {
                outCipher.update(
                                 buffer.array(), off, len + 4);
            }
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
     * Retrieve the channel designated by the given packet
     *
     * @param buffer the incoming packet
     * @return the target channel
     * @throws IOException if the channel does not exists
     */
    protected Channel getChannel(Buffer buffer) throws IOException {
        int recipient = buffer.getInt();
        Channel channel = channels.get(recipient);
        if (channel == null) {
            buffer.rpos(buffer.rpos() - 5);
            SSHConstants.Message cmd = buffer.getCommand();
            throw new SSHException("Received " + cmd + " on unknown channel " + recipient);
        }
        return channel;
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

    protected void handleMessage(Buffer buffer)
    {
        SSHConstants.Message cmd = buffer.getCommand();
        log.debug("Received packet {}", cmd);
        switch (cmd) {
            case SSH_MSG_DISCONNECT: {
                int code = buffer.getInt();
                String msg = buffer.getString();
                log.info("Received SSH_MSG_DISCONNECT (reason={}, msg={})", code, msg);
                close(false);
                break;
            }
            case SSH_MSG_UNIMPLEMENTED: {
                int code = buffer.getInt();
                log.info("Received SSH_MSG_UNIMPLEMENTED #{}", code);
                break;
            }
            case SSH_MSG_DEBUG: {
                boolean display = buffer.getBoolean();
                String msg = buffer.getString();
                log.info("Received SSH_MSG_DEBUG (display={}) '{}'", display, msg);
                break;
            }
            case SSH_MSG_IGNORE:
                log.info("Received SSH_MSG_IGNORE");
                break;
            default:
                switch (state) {
                    case ReceiveKexInit:
                        if (cmd != SSHConstants.Message.SSH_MSG_KEXINIT) {
                            log.error("Ignoring command " + cmd + " while waiting for " + SSHConstants.Message.SSH_MSG_KEXINIT);
                            break;
                        }
                        log.info("Received SSH_MSG_KEXINIT");
                        receiveKexInit(buffer);
                        negotiate();
                        kex = NamedFactory.Utils.create(factoryManager.getKeyExchangeFactories(), negotiated[SSHConstants.PROPOSAL_KEX_ALGS]);
                        kex.init(this, serverVersion.getBytes(), clientVersion.getBytes(), I_S, I_C);
                        setState(State.Kex);
                        break;
                    case Kex:
                        buffer.rpos(buffer.rpos() - 1);
                        if (kex.next(buffer)) {
                            checkHost();
                            sendNewKeys();
                            setState(State.ReceiveNewKeys);
                        }
                        break;
                    case ReceiveNewKeys:
                        if (cmd != SSHConstants.Message.SSH_MSG_NEWKEYS) {
                            disconnect(SSHConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet SSH_MSG_NEWKEYS, got " + cmd);
                            return;
                        }
                        log.info("Received SSH_MSG_NEWKEYS");
                        receiveNewKeys(false);
                        sendAuthRequest();
                        setState(State.AuthRequestSent);
                        break;
                    case AuthRequestSent:
                        if (cmd != SSHConstants.Message.SSH_MSG_SERVICE_ACCEPT) {
                            disconnect(SSHConstants.SSH2_DISCONNECT_PROTOCOL_ERROR, "Protocol error: expected packet SSH_MSG_SERVICE_ACCEPT, got " + cmd);
                            return;
                        }
                        setState(State.WaitForAuth);
                        break;
                    case WaitForAuth:
                        // We're waiting for the client to send an authentication request
                        // TODO: handle unexpected incoming packets
                        break;
                    case UserAuth:
                        if (userAuth == null) {
                            throw new IllegalStateException("State is userAuth, but no user auth pending!!!");
                        }
                        buffer.rpos(buffer.rpos() - 1);
                        switch (userAuth.next(buffer)) {
                             case Success:
                                 authed = true;
                                 setState(State.Running);
                                 break;
                             case Failure:
                                 userAuth = null;
                                 setState(State.WaitForAuth);
                                 break;
                             case Continued:
                                 break;
                        }
                        break;
                    case Running:
                        switch (cmd) {
                            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                                channelOpenConfirmation(buffer);
                                break;
                            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                                channelOpenFailure(buffer);
                                break;
                            case SSH_MSG_CHANNEL_REQUEST:
                                channelRequest(buffer);
                                break;
                            case SSH_MSG_CHANNEL_DATA:
                                channelData(buffer);
                                break;
                            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                                channelExtendedData(buffer);
                                break;
                            case SSH_MSG_CHANNEL_FAILURE:
                                channelFailure(buffer);
                                break;
                            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                                channelWindowAdjust(buffer);
                                break;
                            case SSH_MSG_CHANNEL_EOF:
                                channelEof(buffer);
                                break;
                            case SSH_MSG_CHANNEL_CLOSE:
                                channelClose(buffer);
                                break;
                            // TODO: handle other requests
                        }
                        break;
                }
        }
    }

    public void run()
    {
        while (!done)
        {
            // * take from outPackets and write to server
            // * for packets from server
            // - will be either packets to be handled in this thread's context
            // immediately e.g. key reexchange
            // - data for a specific channel: will be written to its inputstream
            // * on session close -- close events go to the channels' streams
            // (?)
        }
    }

    /**
     * Send our identification.
     * 
     * @param ident
     *            our identification to send
     */
    protected void sendIdentification(String ident) throws InterruptedIOException
    {
        writeRaw((ident + "\r\n").getBytes());
    }

    /**
     * Send the key exchange initialization packet.
     * This packet contains random data along with our proposal.
     *
     * @param proposal our proposal for key exchange negociation
     * @return the sent packet which must be kept for later use
     * @throws IOException if an error occured sending the packet
     */
    protected byte[] sendKexInit(String[] proposal) throws IOException {
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_KEXINIT);
        int p = buffer.wpos();
        buffer.wpos(p + 16);
        random.fill(buffer.array(), p, 16);
        for (String s : proposal) {
            buffer.putString(s);
        }
        buffer.putByte((byte) 0);
        buffer.putInt(0);
        byte[] data = buffer.getCompactData();
        writePacket(buffer);
        return data;
    }

    public void writePacket(Buffer payload) throws IOException
    {
        // Synchronize all write requests as needed by the encoding algorithm
        // and also queue the write request in this synchronized block to ensure
        // packets are sent in the correct order        
        synchronized (encodeLock)
        {
            encode(payload);
            writeRaw(payload.array());
        }
    }

    public void writeRaw(byte[] raw) throws InterruptedIOException
    {
        try
        {
            outQ.put(raw);
        } catch (InterruptedException e)
        {
            InterruptedIOException ioe = new InterruptedIOException();
            ioe.initCause(e);
            throw ioe;
        }
    }
    
    /**
     * Send an unimplemented packet.  This packet should contain the
     * sequence id of the usupported packet: this number is assumed to
     * be the last packet received.
     *
     * @throws IOException if an error occured sending the packet
     */
    protected void notImplemented() throws IOException {
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_UNIMPLEMENTED);
        buffer.putInt(seqi - 1);
        writePacket(buffer);
    }

    /**
     * Compute the negociated proposals by merging the client and
     * server proposal.  The negocatiated proposal will be stored in
     * the {@link #negociated} property.
     */
    protected void negotiate() {
        String[] guess = new String[SSHConstants.PROPOSAL_MAX];
        for (int i = 0; i < SSHConstants.PROPOSAL_MAX; i++) {
            String[] c = clientProposal[i].split(",");
            String[] s = serverProposal[i].split(",");
            for (String ci : c) {
                for (String si : s) {
                    if (ci.equals(si)) {
                        guess[i] = ci;
                        break;
                    }
                }
                if (guess[i] != null) {
                    break;
                }
            }
            if (guess[i] == null && i != SSHConstants.PROPOSAL_LANG_CTOS && i != SSHConstants.PROPOSAL_LANG_STOC) {
                throw new IllegalStateException("Unable to negociate");
            }
        }
        negotiated = guess;
    }

    private void sendAuthRequest() throws Exception {
        log.info("Send SSH_MSG_SERVICE_REQUEST for ssh-userauth");
        Buffer buffer = createBuffer(SSHConstants.Message.SSH_MSG_SERVICE_REQUEST);
        buffer.putString("ssh-userauth");
        writePacket(buffer);
    }

    private void channelOpenConfirmation(Buffer buffer) throws IOException {
        AbstractClientChannel channel = (AbstractClientChannel) getChannel(buffer);
        log.info("Received SSH_MSG_CHANNEL_OPEN_CONFIRMATION on channel {}", channel.getId());
        int recipient = buffer.getInt();
        int rwsize = buffer.getInt();
        int rmpsize = buffer.getInt();
        channel.internalOpenSuccess(recipient, rwsize, rmpsize);
    }

    private void channelOpenFailure(Buffer buffer) throws IOException {
        AbstractClientChannel channel = (AbstractClientChannel) getChannel(buffer);
        log.info("Received SSH_MSG_CHANNEL_OPEN_FAILURE on channel {}", channel.getId());
        channels.remove(channel.getId());
        channel.internalOpenFailure(buffer);
    }
    private void sendClientIdentification() {
        clientVersion = "SSH-2.0-" + getFactoryManager().getVersion();
        sendIdentification(clientVersion);
    }

    private void sendKexInit() throws Exception {
        clientProposal = createProposal(KeyPairProvider.SSH_RSA + "," + KeyPairProvider.SSH_DSS);
        I_C = sendKexInit(clientProposal);
    }

    private void receiveKexInit(Buffer buffer) throws Exception {
        serverProposal = new String[SSHConstants.PROPOSAL_MAX];
        I_S = receiveKexInit(buffer, serverProposal);
    }
    
    protected boolean readIdentification(Buffer buffer) throws IOException {
        serverVersion = doReadIdentification(buffer);
        if (serverVersion == null) {
            return false;
        }
        log.info("Server version string: {}", serverVersion);
        if (!serverVersion.startsWith("SSH-2.0-")) {
            throw new SSHException(SSHConstants.SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED,
                                   "Unsupported protocol version: " + serverVersion);
        }
        return true;
    }    
    
}