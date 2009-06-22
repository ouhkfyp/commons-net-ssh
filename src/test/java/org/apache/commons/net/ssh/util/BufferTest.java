package org.apache.commons.net.ssh.util;

import static org.junit.Assert.assertEquals;

import java.io.UnsupportedEncodingException;

import org.apache.commons.net.ssh.util.Buffer.BufferException;
import org.junit.Before;
import org.junit.Test;

/**
 * Sample unit test for testing {@link Buffer} functionality
 * @author rorywinston
 *
 */
public class BufferTest {
	private Buffer buf;

	@Before()
	public void setUp() throws UnsupportedEncodingException {
		byte[] data = "Hello".getBytes("UTF-8");
		buf = new Buffer(data);
	}

	@Test
	public void testBufferPosition() throws UnsupportedEncodingException {
		assertEquals(5, buf.wpos());
		assertEquals(0, buf.rpos());
		assertEquals(5, buf.available());

		// read some bytes
		byte b = buf.getByte();
		assertEquals(b, (byte)'H');

		assertEquals(1, buf.rpos());
		assertEquals(4, buf.available());
	}

	@Test(expected=BufferException.class)
	public void testUnderflow() {
		// exhaust the buffer
		for (int i = 0; i < 5; ++i)
			buf.getByte();		 
		// underflow
		buf.getByte();
	}
}
