package org.apache.commons.net.ssh.util;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.InetAddress;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.net.ssh.HostKeyVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KnownHosts implements HostKeyVerifier {
	
	private final Logger log = LoggerFactory.getLogger(getClass());
	
	public static String[] guessLocations()
	{
		String kh = (System.getProperty("user.home")  + File.separator + 
					(System.getProperty("os.name").startsWith("Windows") ? "ssh" : ".ssh") +
					File.separator +  "known_hosts");
		return new String[] { kh, kh + "2" };
	}
	
	private Map<String, List<PublicKey>> entries = new HashMap<String, List<PublicKey>>();
	
	KnownHosts()
	{
		this(guessLocations());
	}

	KnownHosts(String[] locations)
	{
		for (String l: locations)
			readIn(l);
	}
	
	public void add(final String host, final PublicKey key)
	{
		List<PublicKey> l = entries.get(host);
		if (l != null)
			l.add(key);
		else
			entries.put(host, new LinkedList<PublicKey>(){{this.add(key);}});
	}
	
	private void readIn(String l) {
		try
		{
			BufferedReader br = new BufferedReader(new FileReader(l));
			String line;
			while ((line = br.readLine()) != null)
				fromLine(line);
		}
		catch (Exception e)
		{
			log.error("Error loading {}: {}", e);
		}
	}

	private void fromLine(String line) {
		String[] parts = line.split(" "); // { host,  keytype, key }
		if (parts.length != 3)
			return;
	}
	
	public boolean verify(InetAddress host, PublicKey key) {
		return false;
	}

}

//private static boolean isHashed(String host)
//{
//	return host.startsWith("|1|");
//}
