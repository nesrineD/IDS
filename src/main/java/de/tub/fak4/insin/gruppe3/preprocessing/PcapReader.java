package de.tub.fak4.insin.gruppe3.preprocessing;

import java.net.Inet4Address;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.tub.fak4.insin.gruppe3.model.DbConnector;

/**
 * Read a given Pcap-File and extract the TCP/IP header information the
 * pre-defined database
 *
 * @author nesrine
 *		
 */
public class PcapReader {
	
	/** The logger for this class */
	private static final Logger LOGGER = LoggerFactory.getLogger(PcapReader.class);
	
	/** The DB-connector handling all SQL-statements executions */
	private final DbConnector dbConnector;
	
	/** The pseudo-RNG used to generate ID-values */
	private SecureRandom prng;
	/** The algorithm used to generate the random numbers */
	private static final String PRNG_ALGORITHM = "SHA1PRNG";
	
	/**
	 * Constructor database
	 *
	 * @param dbUrl the URL to the DB
	 * @param dbUserName the user-name required to access the DB
	 * @param dbPass the password required to access the DB
	 * @param dbSchema the schemata used to store the Pcap-data
	 */
	public PcapReader(DbConnector dbConnector) {
		
		this.dbConnector = dbConnector;
		try {
			prng = SecureRandom.getInstance(PRNG_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Unable to instantiate the PRNG with the algorithm: " + PRNG_ALGORITHM);
		}
	}
	
	/**
	 * Reads a given Pcap-file and extract various information from TCP/IP
	 * headers into the DB. The extracted information involves srcIP, destIP,
	 * srcPort, destPort, packetLength, flags, etc.
	 *
	 * @param filePath the path to the Pcap-file
	 * @param dbTableName the name of the DB table to hold the raw data
	 *		
	 * @return {@code 0} if data is successfully written into DB, {@code -1}
	 *         otherwise
	 *
	 * @throws PcapNativeException
	 * @throws NotOpenException
	 */
	public int readPcapFileIntoDB(String filePath, String dbTableName)
			throws PcapNativeException, NotOpenException {
			
		LOGGER.debug("Reading Pcap file: " + filePath);
		
		// Input check
		if ((filePath == null) || filePath.isEmpty()) {
			LOGGER.error("Invalid Pcap-file! Read-operation cancelled!");
			return -1;
		}
		
		/*
		 * // Create all relevant DB tables if (generateTables() != 0) {
		 * LOGGER.error(
		 * "Unable to generate necessary DB tables to hold the raw data information! Read-operation cancelled!"
		 * ); return -1; }
		 */
		
		// Change the filename and the path of the tcpdump file or pcap file
		PcapHandle handle = Pcaps.openOffline(filePath);
		Packet packet;
		
		// Iterate through every packet found in the Pcap-file
		while ((packet = handle.getNextPacket()) != null) {
			
			// Arrays to hold various information extracted from the packet
			String[] packetHeaderInfo = new String[26];
			
			// Time-stamp used to mark the packet in the DB
			Timestamp timeStamp = new Timestamp(handle.getTimestampInts() * 1000L);
			timeStamp.setNanos(handle.getTimestampMicros() * 1000);
			
			// Extract header information from the packet
			if (packet.contains(TcpPacket.class)) {
				packetHeaderInfo = handleTcpPackets(packet, timeStamp);
			} else if (packet.contains(UdpPacket.class)) {
				packetHeaderInfo = handleUdpPackets(packet, timeStamp);
			} else if (packet.contains(IcmpV4CommonPacket.class)) {
				packetHeaderInfo = handleIcmpPacket(packet, timeStamp);
			}
			
			// Insert the values to the appropriate table
			if (dbConnector.insertRawData(packetHeaderInfo, dbTableName) == -1) {
				LOGGER.error("Unable to insert the raw data into the table: " + dbTableName);
			}
		}
		
		LOGGER.debug("Pcap file " + filePath + " successfully read and written to DB.");
		return 0;
	}
	
	/**
	 * Generate necessary tables for the Pcap-data information. This includes:
	 * <ol>
	 * <li>An IP-mapping table: {@code IP}</li>
	 * <li>Tables to store raw data information from Pcap files: {@code TRAIN},
	 * {@code VALIDATION}, and {@code TESTING}</li>
	 * <li>Table to store aggregated (per TCP session) data information:
	 * {@code TRAIN_mappedTable}, {@code VALIDATION_mappedTable}, and
	 * {@code TESTING_mappedTable}</li>
	 * <li>Final tables to store the relevant feature vectors:
	 * {@code TRAIN_finalTable}, {@code VALIDATION_finalTable}, and
	 * {@code TESTING_finalTable}</li>
	 * </ol>
	 *
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	public int generateTables() {
		
		LOGGER.debug("Creating all necessary tables to store Pcap information.");
		int counter = 0;
		
		// ===================================================
		// ===================== IP TABLE ====================
		// ===================================================
		
		if (dbConnector.createIpMappingTable() == 0) {
			LOGGER.debug("IP mapping table: * " + DbConnector.IP_TABLE_NAME + " * successfully created.");
			counter++;
		}
		
		// ====================================================
		// ===================== RAW TABLE ====================
		// ====================================================
		
		if (dbConnector.createDbTableForRawData(DbConnector.TRAIN_TABLE_NAME) == 0) {
			LOGGER.debug("Train table: * " + DbConnector.TRAIN_TABLE_NAME + " * successfully created.");
			counter++;
		}
		if (dbConnector.createDbTableForRawData(DbConnector.VALIDATION_TABLE_NAME) == 0) {
			LOGGER.debug("Validation table: * " + DbConnector.VALIDATION_TABLE_NAME + " * successfully created.");
			counter++;
		}
		if (dbConnector.createDbTableForRawData(DbConnector.TESTING_TABLE_NAME) == 0) {
			LOGGER.debug("Test table: * " + DbConnector.TESTING_TABLE_NAME + " * successfully created.");
			counter++;
		}
		
		for (int i = 1; i <= 5; i++) {
			
			if (dbConnector.createDbTableForRawData("TCP_3" + i + "_in") == 0) {
				LOGGER.debug("Table: * TCP_3" + i + "_in * successfully created.");
				counter++;
			}
			if (dbConnector.createDbTableForRawData("TCP_3" + i + "_out") == 0) {
				LOGGER.debug("Table: * TCP_3" + i + "_out * successfully created.");
				counter++;
			}
			
			if (dbConnector.createDbTableForRawData("TCP_4" + i + "_in") == 0) {
				LOGGER.debug("Table: * TCP_4" + i + "_in * successfully created.");
				counter++;
			}
			if (dbConnector.createDbTableForRawData("TCP_4" + i + "_out") == 0) {
				LOGGER.debug("Table: * TCP_3" + i + "_out * successfully created.");
				counter++;
			}
			
			if (dbConnector.createDbTableForRawData("TCP_5" + i + "_in") == 0) {
				LOGGER.debug("Table: * TCP_5" + i + "_in * successfully created.");
				counter++;
			}
			if (dbConnector.createDbTableForRawData("TCP_5" + i + "_out") == 0) {
				LOGGER.debug("Table: * TCP_3" + i + "_out * successfully created.");
				counter++;
			}
			
		}
		
		// ====================================================
		// ================= AGGREGATED TABLE =================
		// ====================================================
		
		if (dbConnector.createDbTableForAggregatedData(
				DbConnector.TRAIN_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX) == 0) {
			LOGGER.debug("Aggregated train table: * " + DbConnector.TRAIN_TABLE_NAME
					+ DbConnector.AGGREGATED_TABLE_SUFFIX + " * succesfully created.");
			counter++;
		}
		if (dbConnector.createDbTableForAggregatedData(
				DbConnector.VALIDATION_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX) == 0) {
			LOGGER.debug("Aggregated validation table: * " + DbConnector.VALIDATION_TABLE_NAME
					+ DbConnector.AGGREGATED_TABLE_SUFFIX + " * succesfully created.");
			counter++;
		}
		if (dbConnector.createDbTableForAggregatedData(
				DbConnector.TESTING_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX) == 0) {
			LOGGER.debug("Aggregated testing table: * " + DbConnector.TESTING_TABLE_NAME
					+ DbConnector.AGGREGATED_TABLE_SUFFIX + " * succesfully created.");
			counter++;
		}
		
		LOGGER.debug("A total of * " + counter + " * tables are created.");
		
		return 0;
	}
	
	/**
	 * Extract header information from a TCP packet and delivers the information
	 * in {@link String}[] format
	 *
	 * @param tcpPacket the TCP-{@link Packet}
	 * @param timeStamp the {@link Timestamp} when the {@link Packet} is being
	 *        processed
	 *
	 * @return {@link String}[] containing all header information from the TCP
	 *         packet
	 */
	private String[] handleTcpPackets(Packet tcpPacket, Timestamp timeStamp) {
		
		if ((tcpPacket == null) || (timeStamp == null)) {
			LOGGER.error("Invalid TCP-packet and/or timestamp!");
			return null;
		}
		
		String[] packetHeaderInfo = new String[26];
		
		// Self-assigned ID of the packet
		packetHeaderInfo[0] = new Integer(prng.nextInt()).toString();
		
		// Source & destination IPs (in IPv4 format)
		Inet4Address srcIP = tcpPacket.get(IpV4Packet.class).getHeader().getSrcAddr();
		String sourceIP = tcpPacket.get(IpV4Packet.class).getHeader().getSrcAddr().toString();
		Inet4Address dstIP = tcpPacket.get(IpV4Packet.class).getHeader().getSrcAddr();
		String destinationIP = tcpPacket.get(IpV4Packet.class).getHeader().getDstAddr().toString();
		
		packetHeaderInfo[1] = sourceIP;
		packetHeaderInfo[2] = destinationIP;
		// Name of the protocol
		packetHeaderInfo[3] = tcpPacket.get(IpV4Packet.class).getHeader().getProtocol().name();
		// Length of the packet-payload
		packetHeaderInfo[4] = Integer.toString(tcpPacket.getRawData().length);
		
		if (tcpPacket.get(IpV4Packet.class).getHeader().getDontFragmentFlag()) {
			packetHeaderInfo[5] = "1";
		} else {
			packetHeaderInfo[5] = "0";
		}
		
		if (tcpPacket.get(IpV4Packet.class).getHeader().getMoreFragmentFlag()) {
			packetHeaderInfo[6] = "1";
		} else {
			packetHeaderInfo[6] = "0";
		}
		
		if (tcpPacket.get(IpV4Packet.class).getHeader().getReservedFlag()) {
			packetHeaderInfo[7] = "1";
		} else {
			packetHeaderInfo[7] = "0";
		}
		
		packetHeaderInfo[8] = Integer.toString(tcpPacket.get(IpV4Packet.class).getHeader().getTtl() & 0xFF);
		packetHeaderInfo[9] = Integer.toString(tcpPacket.get(IpV4Packet.class).getHeader().getTos().value() & 0xFF);
		
		if (tcpPacket.get(TcpPacket.class).hasValidChecksum(srcIP, dstIP, false)) {
			packetHeaderInfo[10] = "0";// OK
		} else {
			packetHeaderInfo[10] = "1";// Not OK
		}
		
		packetHeaderInfo[11] = Integer.toString(tcpPacket.get(IpV4Packet.class).getPayload().length());
		
		packetHeaderInfo[12] = timeStamp.toString();
		packetHeaderInfo[13] = tcpPacket.get(TcpPacket.class).getHeader().getSrcPort().valueAsString();
		packetHeaderInfo[14] = tcpPacket.get(TcpPacket.class).getHeader().getDstPort().valueAsString();
		
		if (tcpPacket.get(TcpPacket.class).getHeader().getPsh() == true) {
			packetHeaderInfo[15] = "1";
		} else {
			packetHeaderInfo[15] = "0";
		}
		if (tcpPacket.get(TcpPacket.class).getHeader().getUrg() == true) {
			packetHeaderInfo[16] = "1";
		} else {
			packetHeaderInfo[16] = "0";
		}
		if (tcpPacket.get(TcpPacket.class).getHeader().getAck() == true) {
			packetHeaderInfo[17] = "1";
		} else {
			packetHeaderInfo[17] = "0";
		}
		if (tcpPacket.get(TcpPacket.class).getHeader().getRst() == true) {
			packetHeaderInfo[18] = "1";
		} else {
			packetHeaderInfo[18] = "0";
		}
		if (tcpPacket.get(TcpPacket.class).getHeader().getSyn() == true) {
			packetHeaderInfo[19] = "1";
		} else {
			packetHeaderInfo[19] = "0";
		}
		if (tcpPacket.get(TcpPacket.class).getHeader().getFin() == true) {
			packetHeaderInfo[20] = "1";
		} else {
			packetHeaderInfo[20] = "0";
		}
		
		packetHeaderInfo[21] = Integer.toString(tcpPacket.get(TcpPacket.class).getHeader().getReserved() & 0xFF);
		packetHeaderInfo[22] = Integer.toString(tcpPacket.get(TcpPacket.class).getHeader().getWindow());
		packetHeaderInfo[23] = Integer.toString(tcpPacket.get(TcpPacket.class).getHeader().getAcknowledgmentNumber());
		packetHeaderInfo[24] = Integer.toString(tcpPacket.get(TcpPacket.class).getHeader().getSequenceNumber());
		packetHeaderInfo[25] = "0";
		
		return packetHeaderInfo;
	}
	
	/**
	 * Extract header information from a UDP packet and delivers the information
	 * in {@link String}[] format
	 *
	 * @param udpPacket the UDP-{@link Packet}
	 * @param timeStamp the {@link Timestamp} when the {@link Packet} is being
	 *        processed
	 *
	 * @return {@link String}[] containing all header information from the UDP
	 *         packet
	 */
	private String[] handleUdpPackets(Packet udpPacket, Timestamp timeStamp) {
		
		if ((udpPacket == null) || (timeStamp == null)) {
			LOGGER.error("Invalid UDP-packet and/or timestamp!");
			return null;
		}
		
		String[] packetInfo = new String[26];
		
		packetInfo[0] = new Integer(prng.nextInt()).toString();
		
		// Source & destination IP
		Inet4Address srcIP = udpPacket.get(IpV4Packet.class).getHeader().getSrcAddr();
		String sourceIP = udpPacket.get(IpV4Packet.class).getHeader().getSrcAddr().toString();// ipv4
		Inet4Address dstIP = udpPacket.get(IpV4Packet.class).getHeader().getSrcAddr();
		String destinationIP = udpPacket.get(IpV4Packet.class).getHeader().getDstAddr().toString();
		
		packetInfo[1] = sourceIP;
		packetInfo[2] = destinationIP;
		
		packetInfo[3] = udpPacket.get(IpV4Packet.class).getHeader().getProtocol().name();
		packetInfo[4] = Integer.toString(udpPacket.getRawData().length);
		
		// ===========================================
		// ============== Packet flags ===============
		// ===========================================
		if (udpPacket.get(IpV4Packet.class).getHeader().getDontFragmentFlag()) {
			packetInfo[5] = "1";
		} else {
			packetInfo[5] = "0";
		}
		if (udpPacket.get(IpV4Packet.class).getHeader().getMoreFragmentFlag()) {
			packetInfo[6] = "1";
		} else {
			packetInfo[6] = "0";
		}
		if (udpPacket.get(IpV4Packet.class).getHeader().getReservedFlag()) {
			packetInfo[7] = "1";
		} else {
			packetInfo[7] = "0";
		}
		// ==================================
		
		// TTL
		packetInfo[8] = Integer.toString(udpPacket.get(IpV4Packet.class).getHeader().getTtl() & 0xFF);
		packetInfo[9] = Integer.toString(udpPacket.get(IpV4Packet.class).getHeader().getTos().value() & 0xFF);
		
		if (udpPacket.get(UdpPacket.class).hasValidChecksum(srcIP, dstIP, false)) {
			packetInfo[10] = "0";// OK
		} else {
			packetInfo[10] = "1";// Not OK
		}
		
		packetInfo[11] = Integer.toString(udpPacket.get(IpV4Packet.class).getPayload().length());
		
		packetInfo[12] = timeStamp.toString();
		packetInfo[13] = udpPacket.get(UdpPacket.class).getHeader().getSrcPort().valueAsString();
		packetInfo[14] = udpPacket.get(UdpPacket.class).getHeader().getDstPort().valueAsString();
		packetInfo[15] = "";
		packetInfo[16] = "";
		packetInfo[17] = "";
		packetInfo[18] = "";
		packetInfo[19] = "";
		packetInfo[20] = "";
		packetInfo[21] = "";
		packetInfo[22] = "";
		packetInfo[23] = "";
		packetInfo[24] = "";
		packetInfo[25] = "0";
		
		return packetInfo;
	}
	
	/**
	 * Extract header information from a ICMP packet and delivers the
	 * information in {@link String}[] format
	 *
	 * @param udpPacket the ICMP-{@link Packet}
	 * @param timeStamp the {@link Timestamp} when the {@link Packet} is being
	 *        processed
	 *
	 * @return {@link String}[] containing all header information from the ICMP
	 *         packet
	 */
	private String[] handleIcmpPacket(Packet icmpPacket, Timestamp timeStamp) {
		
		if ((icmpPacket == null) || (timeStamp == null)) {
			LOGGER.error("Invalid ICMP-packet and/or timestamp!");
			return null;
		}
		
		String[] packetInfo = new String[26];
		
		packetInfo[0] = new Integer(prng.nextInt()).toString();
		
		// Source & Destination IP
		@SuppressWarnings("unused")
		Inet4Address srcIP = icmpPacket.get(IpV4Packet.class).getHeader().getSrcAddr();
		String sourceIP = icmpPacket.get(IpV4Packet.class).getHeader().getSrcAddr().toString();// ipv4
		@SuppressWarnings("unused")
		Inet4Address dstIP = icmpPacket.get(IpV4Packet.class).getHeader().getSrcAddr();
		String destinationIP = icmpPacket.get(IpV4Packet.class).getHeader().getDstAddr().toString();
		
		packetInfo[1] = sourceIP;
		packetInfo[2] = destinationIP;
		
		packetInfo[3] = icmpPacket.get(IpV4Packet.class).getHeader().getProtocol().name();
		packetInfo[4] = Integer.toString(icmpPacket.getRawData().length); // packet
		
		if (icmpPacket.get(IpV4Packet.class).getHeader().getDontFragmentFlag()) {
			packetInfo[5] = "1";
		} else {
			packetInfo[5] = "0";
		}
		if (icmpPacket.get(IpV4Packet.class).getHeader().getMoreFragmentFlag()) {
			packetInfo[6] = "1";
		} else {
			packetInfo[6] = "0";
		}
		
		if (icmpPacket.get(IpV4Packet.class).getHeader().getReservedFlag()) {
			packetInfo[7] = "1";
		} else {
			packetInfo[7] = "0";
		}
		
		packetInfo[8] = Integer.toString(icmpPacket.get(IpV4Packet.class).getHeader().getTtl() & 0xFF);
		packetInfo[9] = Integer.toString(icmpPacket.get(IpV4Packet.class).getHeader().getTos().value() & 0xFF);
		
		if (icmpPacket.get(IcmpV4CommonPacket.class).hasValidChecksum(false)) {
			packetInfo[10] = "0";// OK
		} else {
			packetInfo[10] = "1";// Not OK
		}
		
		packetInfo[11] = Integer.toString(icmpPacket.get(IpV4Packet.class).getPayload().length());
		packetInfo[12] = timeStamp.toString();
		packetInfo[13] = Integer
				.toString(icmpPacket.get(IcmpV4CommonPacket.class).getHeader().getType().value() & 0xFF);
		packetInfo[14] = "";
		packetInfo[15] = "";
		packetInfo[16] = "";
		packetInfo[17] = "";
		packetInfo[18] = "";
		packetInfo[19] = "";
		packetInfo[20] = "";
		packetInfo[21] = "";
		packetInfo[22] = "";
		packetInfo[23] = "";
		packetInfo[24] = "";
		packetInfo[25] = "0";
		
		return packetInfo;
	}
	
}
