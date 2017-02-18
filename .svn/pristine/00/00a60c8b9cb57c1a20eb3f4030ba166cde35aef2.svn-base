package de.tub.fak4.insin.gruppe3.model;

import java.io.File;
import java.io.FileNotFoundException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles the communication between Java and DB, currently only supports SQL-DB
 *
 * @author alwin
 * 		
 */
public class DbConnector {
	
	/** The logger for this class */
	private static final Logger LOGGER = LoggerFactory.getLogger(DbConnector.class);
	
	/** The name of the class used to communicate with the SQL-DB */
	private final String dbInterfaceClassName;
	/** The URL of the DB itself */
	private final String dbUrl;
	/** The DB schemata used to store the Pcap-data */
	private final String dbSchema;
	
	/** The name of the table that holds the IP mapping info */
	public static final String IP_TABLE_NAME = "IP";
	/** The name (prefix) of the table that holds all training data info */
	public static final String TRAIN_TABLE_NAME = "Train";
	/** The name (prefix) of the table that holds all validation data info */
	public static final String VALIDATION_TABLE_NAME = "Validation";
	/** The name (prefix) of the table that holds all testing data info */
	public static final String TESTING_TABLE_NAME = "Testing";
	
	public static final String AGGREGATED_TABLE_SUFFIX = "_mappedTable";
	
	public static final String FEATURE_TABLE_SUFFIX = "_finalTable";
	
	/** The connection established to a DB */
	private Connection dbConnection;
	
	/**
	 * Constructor
	 *
	 * @param dbInterfaceClassName The name of the class used to communicate
	 *        with the SQL-DB
	 * @param dbUrl The URL of the DB itself
	 * @param dbUserName User name used to access DB
	 * @param dbPass Password used to access DB
	 * @param dbSchema The DB schemata used to store the Pcap-data
	 */
	public DbConnector(String dbInterfaceClassName, String dbUrl, String dbUserName, String dbPass, String dbSchema) {
		
		this.dbInterfaceClassName = dbInterfaceClassName;
		this.dbUrl = dbUrl;
		this.dbSchema = dbSchema;
		
		// Load the DB interface
		try {
			Class.forName(dbInterfaceClassName);
			LOGGER.debug("Loaded the DB interface class: " + dbInterfaceClassName);
		} catch (ClassNotFoundException e) {
			LOGGER.error("Unable to found the DB-interface class: " + dbInterfaceClassName);
		}
		
		// Connect to the DB
		try {
			
			dbConnection = DriverManager.getConnection(dbUrl, dbUserName, dbPass);
			LOGGER.debug("Connected to DB: " + dbConnection.getSchema());
		} catch (SQLException e) {
			LOGGER.error("Failer when trying to connect to DB: " + dbUrl);
		}
		
		// Create the necessary schema
		if (createDbSchema(dbSchema) == 0) {
			LOGGER.debug("DB schema: *" + dbSchema + "* successfully created.");
		}
	}
	
	/**
	 * Insert the raw data information into a specified data table
	 *
	 * @param rawDataPacketHeaderInfo the raw-data itself in {@link String}
	 *        {@code []} format
	 * @param rawDataTableName the name of the table where the raw-data should
	 *        be inserted into
	 * 		
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	public int insertRawData(String[] rawDataPacketHeaderInfo, String rawDataTableName) {
		
		if (rawDataPacketHeaderInfo.length != 26) {
			LOGGER.error("Invalid packetHeaderInfo length!");
			return -1;
		}
		
		String dbInsertionValue = "'" + rawDataPacketHeaderInfo[0] + "'," + "'" + rawDataPacketHeaderInfo[1] + "',"
				+ "'" + rawDataPacketHeaderInfo[2] + "'," + "'" + rawDataPacketHeaderInfo[3] + "'," + "'"
				+ rawDataPacketHeaderInfo[4] + "'," + "'" + rawDataPacketHeaderInfo[5] + "'," + "'"
				+ rawDataPacketHeaderInfo[6] + "'," + "'" + rawDataPacketHeaderInfo[7] + "'," + "'"
				+ rawDataPacketHeaderInfo[8] + "'," + "'" + rawDataPacketHeaderInfo[9] + "'," + "'"
				+ rawDataPacketHeaderInfo[10] + "'," + "'" + rawDataPacketHeaderInfo[11] + "'," + "'"
				+ rawDataPacketHeaderInfo[12] + "'," + "'" + rawDataPacketHeaderInfo[13] + "'," + "'"
				+ rawDataPacketHeaderInfo[14] + "'," + "'" + rawDataPacketHeaderInfo[15] + "'," + "'"
				+ rawDataPacketHeaderInfo[16] + "'," + "'" + rawDataPacketHeaderInfo[17] + "'," + "'"
				+ rawDataPacketHeaderInfo[18] + "'," + "'" + rawDataPacketHeaderInfo[19] + "'," + "'"
				+ rawDataPacketHeaderInfo[20] + "'," + "'" + rawDataPacketHeaderInfo[21] + "'," + "'"
				+ rawDataPacketHeaderInfo[22] + "'," + "'" + rawDataPacketHeaderInfo[23] + "'," + "'"
				+ rawDataPacketHeaderInfo[24] + "'," + "'" + rawDataPacketHeaderInfo[25] + "'";
				
		String insertRawTrainDataCommand = "INSERT INTO " + rawDataTableName + " VALUES (" + dbInsertionValue + ")";
		
		if (updateDB(insertRawTrainDataCommand) == 0) {
			// LOGGER.debug("Succesfully inserted raw data information into
			// table: "
			// + rawDataTableName);
			return 0;
		}
		
		return -1;
	}
	
	/**
	 * Insert all unique IP-addresses into the IP-mapping table
	 *
	 * @param ipTableName
	 * 		
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	public int insertAllIpMapping() {
		
		String insertIpMappingQuery = "INSERT INTO " + IP_TABLE_NAME + " (IP)" + //
				" SELECT DISTINCT completeIpTable.IP" + //
				" FROM (" + //
				"   SELECT DISTINCT srcIP as IP from " + TRAIN_TABLE_NAME + //
				"   UNION" + //
				"   SELECT DISTINCT destIP as IP from " + TRAIN_TABLE_NAME + //
				"   UNION" + //
				"   SELECT DISTINCT srcIP as IP from " + VALIDATION_TABLE_NAME + //
				"   UNION" + //
				"   SELECT DISTINCT destIP as IP from " + VALIDATION_TABLE_NAME + //
				"   UNION" + //
				"   SELECT DISTINCT srcIP as IP from " + TESTING_TABLE_NAME + //
				"   UNION" + //
				"   SELECT DISTINCT destIP as IP from " + TESTING_TABLE_NAME + //
				" ) completeIpTable;";
				
		if (updateDB(insertIpMappingQuery) == 0) {
			return 0;
		}
		return -1;
	}
	
	/**
	 * Insert all unique IP-addresses into the IP-mapping table
	 * 
	 * @param ipTableName
	 * 		
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	public int insertAllIpMapping(String[] dbs) {
		if (dbs.length < 1)
			return -1;
		String insertIpMappingQuery = "INSERT INTO " + IP_TABLE_NAME + " (IP)" + //
				" SELECT DISTINCT completeIpTable.IP" + //
				" FROM (";
		for (int i = 0; i < dbs.length; i++) {
			
			insertIpMappingQuery += " SELECT DISTINCT srcIP as IP from " + dbs[i] + //
					"   UNION" + //
					"   SELECT DISTINCT destIP as IP from " + dbs[i]; // "
			if (i != dbs.length - 1) // last
				insertIpMappingQuery += "   UNION";
		}
		insertIpMappingQuery += ") completeIpTable;";
		LOGGER.debug("creating Ip map from " + dbs.length + " Tables\n" + insertIpMappingQuery);
		
		if (updateDB(insertIpMappingQuery) == 0) {
			return 0;
		}
		return -1;
	}
	
	/**
	 * Insert all unique aggregated informations into the train_mappedTable;
	 * validation_mappedTable; testing_mappedTable
	 *
	 * @param rawDataTableName the table containing raw-data
	 * @param aggregatedDataTablename the table containing aggregated data
	 * 		
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	public int aggregateRawData(String rawDataTableName, String aggregatedDataTablename) {
		String aggregateDataQuery = "INSERT INTO " + aggregatedDataTablename
		/*
		 * + " (" + "SrcIp," + "DestIp," + "srcPort," + "destPort," + "PL," +
		 * "FSR," + "Duration," + "CS," + "CNT," + "PSH," + "reserved," + "DF,"
		 * + "MF," + "Res," + "TTL," + "TOS," + "URG," + "ACK," + "FIN," +
		 * "SYN," + "RST," + "Category" + ")"
		 */
				+ " SELECT" + // Die Formatierung spinnt hier etwas...
				
		"   COALESCE(NULLIF(" + IP_TABLE_NAME + ".ID,''),0) SrcIp," + //
				"   COALESCE(NULLIF(IpMapDest.ID,''),0) DestIp," + //
				"   COALESCE(NULLIF(rawDataTable.sourcePort,''),0) srcPort," + //
				"   COALESCE(NULLIF(rawDataTable.destPort,''),0) destPort," + //
				"   SUM(COALESCE(NULLIF(rawDataTable.PacketLength,''),0)) PL," + //
				"   SUM(COALESCE(NULLIF(rawDataTable.flags_RST,''),0)+COALESCE(NULLIF(rawDataTable.flags_SYN,''),0)+COALESCE(NULLIF(rawDataTable.flags_ACK,''),0)) FSR,"
				+ //
				"   MAX(COALESCE(NULLIF(TIME_TO_SEC(cast(rawDataTable.packetime as datetime)),''),0)) - MIN(COALESCE(NULLIF(TIME_TO_SEC(cast(rawDataTable.packetime as datetime)),''),0)) Duration,"
				+ //
				"   SUM(COALESCE(NULLIF(rawDataTable.CheckSum,''),0)) CS," + //
				
		"     count(*) CNT," + //
		
		"     SUM(COALESCE(NULLIF(rawDataTable.flags_PSH,''),0)) PSH," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.flags_reserved,''),0)) reserved," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.flags_DF,''),0)) DF," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.flags_MF,''),0)) MF," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.flags_Res,''),0)) Res," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.TTL,''),0)) TTL," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.TOS,''),0)) TOS," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.flags_URG,''),0)) URG," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.flags_ACK,''),0)) ACK," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.flags_FIN,''),0)) FIN," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.flags_SYN,''),0)) SYN," + //
				"     SUM(COALESCE(NULLIF(rawDataTable.flags_RST,''),0)) RST," + //
				"     MAX(COALESCE(NULLIF(rawDataTable.Category,''),0)) Category," + //
				"     MIN(rawDataTable.packetime) PacketTime" + //
				
		"  FROM " + rawDataTableName + " rawDataTable " + //
				"     left join " + IP_TABLE_NAME + " ON rawDataTable.srcIP=" + IP_TABLE_NAME + ".IP" + //
				"     left join (SELECT * FROM " + IP_TABLE_NAME + ") as IpMapDest ON rawDataTable.destIP=IpMapDest.IP"
				+ //
				
		"  WHERE" + //
				"     rawDataTable.protocol='TCP'" + //
				
		"  GROUP BY" + //
				"     COALESCE(NULLIF(" + IP_TABLE_NAME + ".ID,''),0)," + //
				"     COALESCE(NULLIF(IpMapDest.ID,''),0)," + //
				"     COALESCE(NULLIF(rawDataTable.sourcePort,''),0)," + //
				"     COALESCE(NULLIF(rawDataTable.destPort,''),0);";
				
		if (updateDB(aggregateDataQuery) == 0) {
			LOGGER.debug("Aggregation into " + aggregatedDataTablename + " finished!");
			return 0;
		}
		LOGGER.error("Aggregation into " + aggregatedDataTablename + " failed!");
		return -1;
	}
	
	/**
	 * Query the DB with the given SQL-query command
	 *
	 * @param queryCommand the SQL-query command
	 * 		
	 * @return the {@ResultSet} from the SQL-query
	 */
	public ResultSet queryDB(String queryCommand) {
		
		try {
			Statement dbStatement = dbConnection.createStatement();
			return dbStatement.executeQuery(queryCommand);
		} catch (SQLException e) {
			LOGGER.error("Error while executing the query command: " + queryCommand, e);
		}
		
		return null;
	}
	
	/**
	 * Update the DB with the given SQL-update command
	 *
	 * @param updateCommand the SQL-update command
	 * 		
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	public int updateDB(String updateCommand) {
		// Execute Query drop old table
		try (Statement dbStatement = dbConnection.createStatement()) {
			dbStatement.executeUpdate(updateCommand);
			dbStatement.close();
			return 0;
		} catch (SQLException e) {
			LOGGER.error("Error while executing the update command: " + updateCommand, e);
		}
		
		return -1;
	}
	
	/**
	 * Creates a table that holds all IP-adresses
	 *
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	public int createIpMappingTable() {
		
		// Drop the table if it exists already
		String dropExistingTableQuery = "DROP TABLE IF EXISTS " + IP_TABLE_NAME;
		
		String ipTableCreationQuery = "Create table " + IP_TABLE_NAME + "(" + //
				" ID int  NOT NULL AUTO_INCREMENT Primary key," + //
				" IP varchar(100)" + //
				");";
				
		if ((updateDB(dropExistingTableQuery) == 0) && (updateDB(ipTableCreationQuery) == 0)) {
			return 0;
		}
		return -1;
	}
	
	/**
	 * Creates a DB-table to hold raw data information; and drops the old table
	 * if the table name is in used
	 *
	 * @param tableName the name of the DB-table to be created
	 * 		
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	public int createDbTableForRawData(String tableName) {
		
		// Drop the table if it exists already
		String dropExistingTableQuery = "DROP TABLE IF EXISTS " + tableName;
		
		// Prepare the table creation command
		String tableCreationQuery = "CREATE TABLE " + tableName + " (" + //
				"id varchar(20) DEFAULT NULL," + //
				"SrcIp varchar(50) DEFAULT NULL," + //
				"DestIp varchar(50) DEFAULT NULL," + //
				"Protocol varchar(10) DEFAULT NULL," + //
				"PacketLength varchar(50) DEFAULT NULL," + //
				"flags_DF varchar(50) DEFAULT NULL," + //
				"flags_MF varchar(50) DEFAULT NULL," + //
				"flags_Res varchar(50) DEFAULT NULL," + //
				"TTL varchar(50) DEFAULT NULL," + //
				"TOS varchar(50) DEFAULT NULL," + //
				"CheckSum varchar(50) DEFAULT NULL," + //
				"getPayloadLength varchar(50) DEFAULT NULL," + //
				"packetime varchar(50) DEFAULT NULL," + //
				"sourcePort varchar(50) DEFAULT NULL," + //
				"destPort varchar(50" + ") DEFAULT NULL," + //
				"flags_PSH varchar(50) DEFAULT NULL," + //
				"flags_URG varchar(50) DEFAULT NULL," + //
				"flags_ACK varchar(50) DEFAULT NULL," + //
				"flags_RST varchar(50) DEFAULT NULL," + //
				"flags_SYN varchar(50) DEFAULT NULL," + //
				"flags_FIN varchar(50) DEFAULT NULL," + //
				"flags_reserved varchar(50) DEFAULT NULL," + // added
				"window varchar(50) DEFAULT NULL," + // added
				"tcp_ack mediumtext," + //
				"tcp_seq mediumtext," + //
				"Category varchar(50) DEFAULT NULL" + //
				");";
				
		if ((updateDB(dropExistingTableQuery) == 0) && (updateDB(tableCreationQuery) == 0)) {
			return 0;
		}
		
		return -1;
		
	}
	
	/**
	 * Creates a DB-table to hold aggregated data information; and drops the old
	 * table if the table name is in used.
	 *
	 * @param tableName the name of the DB-table to be created
	 * 		
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	public int createDbTableForAggregatedData(String tableName) {
		
		// Drop the table if it exists already
		String dropExistingTableQuery = "DROP TABLE IF EXISTS " + tableName;
		
		// Prepare the table creation command
		String tableCreationQuery = "CREATE TABLE " + tableName + "(" + //
				"SrcIp bigint NULL," + //
				"DestIp bigint NULL," + //
				"srcPort bigint NULL," + //
				"destPort bigint NULL," + //
				"PL bigint NULL," + //
				"FSR int NULL," + //
				"Duration bigint NULL," + //
				"CS int NULL," + //
				"CNT bigint NULL," + //
				"PSH int NULL," + //
				"reserved int NULL," + //
				"DF int NULL," + //
				"MF int NULL," + //
				"Res int NULL," + //
				"TTL int NULL," + //
				"TOS int NULL," + //
				"URG int NULL," + //
				"ACK int NULL," + //
				"FIN int NULL," + //
				"SYN int NULL," + //
				"RST int NULL," + //
				"Category int NOT NULL," + //
				"PacketTime varchar(50) NULL" + //
				");";
				
		if ((updateDB(dropExistingTableQuery) == 0) && (updateDB(tableCreationQuery) == 0)) {
			return 0;
		}
		
		return -1;
	}
	
	/**
	 * Creates a DB schema if it does not exist yet; and choose the DB schema to
	 * be used for future queries
	 *
	 * @param dbSchema the name of the DB schema
	 * 		
	 * @return {@code 0} if successful; {@code -1} otherwise
	 */
	private int createDbSchema(String dbSchema) {
		
		String dbSchemaCreationQuery = "CREATE DATABASE IF NOT EXISTS " + dbSchema + ";";
		String dbSchemaSelectionQuery = "USE " + dbSchema + ";";
		
		if ((updateDB(dbSchemaCreationQuery) == 0) && (updateDB(dbSchemaSelectionQuery) == 0)) {
			return 0;
		}
		
		return -1;
	}
	
	/**
	 * Getter method
	 *
	 * @return The name of the class used to communicate with the SQL-DB
	 */
	public String getDbInterfaceClassName() {
		return dbInterfaceClassName;
	}
	
	/**
	 * Getter method
	 *
	 * @return The URL of the DB itself
	 */
	public String getDbUrl() {
		return dbUrl;
	}
	
	/**
	 * Getter method
	 *
	 * @return the DB schemata used to store the Pcap-data
	 */
	public String getDbSchema() {
		return dbSchema;
	}
	
	/**
	 * Getter method
	 *
	 * @return {@code true} if the connection to DB is still alive;
	 *         {@code false} otherwise
	 */
	public boolean isDbConnectionAlive() {
		try {
			return dbConnection.isValid(0);
		} catch (SQLException e) {
			return false;
		}
	}
	
	/**
	 * Execute a given SQL-script
	 *
	 * @param sqlScriptFilePath the path to the SQL-script file
	 * @throws FileNotFoundException
	 */
	public void executeSQLScript(String sqlScriptFilePath)
			throws FileNotFoundException {
			
		String sqlQueryCommand = "";
		
		Scanner input = new Scanner(new File(sqlScriptFilePath));
		
		while (input.hasNext()) {
			if (input.nextLine().startsWith("Update")) {
				// read script in the variable
				sqlQueryCommand += input.nextLine() + "\r\n";
			}
		}
		
		input.close();
		
		if (!sqlQueryCommand.isEmpty()) {
			updateDB(sqlQueryCommand);
		}
	}
	
}
