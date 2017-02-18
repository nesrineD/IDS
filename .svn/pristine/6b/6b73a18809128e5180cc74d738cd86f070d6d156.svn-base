package de.tub.fak4.insin.gruppe3.preprocessing;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.tub.fak4.insin.gruppe3.model.DbConnector;

/**
 * Aggregates raw data into TCP sessions, which is defined as a unique
 * combination of {@code <srcIP, destIP, srcPort, destPort>}
 * 
 * @author alwin
 * 		
 */
public class TcpSessionAggregator {
	
	/** Logger for this class */
	private static final Logger LOGGER = LoggerFactory.getLogger(TcpSessionAggregator.class);
	
	/** The DB-connector handling all SQL-statements executions */
	private final DbConnector dbConnector;
	
	/**
	 * Constructor
	 * 
	 * @param dbConnector the DB connector instance that will handle the
	 *        communication with the DB
	 */
	public TcpSessionAggregator(DbConnector dbConnector) {
		this.dbConnector = dbConnector;
	}
	
	/**
	 * Aggregate all data from the rawDataTable based on TCP-sessions (unique
	 * combination of {@code <srcIP, destIP, srcPort, destPort>}) and insert
	 * them into the aggregatedDataTable
	 * 
	 * 
	 * @return {@code 0} if successful, {@code -1} otherwise
	 */
	public int aggregateRawData() {
		
		int trainAggregationQueryResult = dbConnector.aggregateRawData(DbConnector.TRAIN_TABLE_NAME,
				DbConnector.TRAIN_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX);
		LOGGER.debug("Aggregated data into: " + DbConnector.TRAIN_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX);
		
		int validationAggregationQueryResult = dbConnector.aggregateRawData(DbConnector.VALIDATION_TABLE_NAME,
				DbConnector.VALIDATION_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX);
		LOGGER.debug(
				"Aggregated data into: " + DbConnector.VALIDATION_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX);
				
		int testingAggregationQueryResult = dbConnector.aggregateRawData(DbConnector.TESTING_TABLE_NAME,
				DbConnector.TESTING_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX);
		LOGGER.debug("Aggregated data into: " + DbConnector.TESTING_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX);
		
		if ((trainAggregationQueryResult != 0) || (validationAggregationQueryResult != 0)
				|| (testingAggregationQueryResult != 0)) {
				
			LOGGER.error("Unable to perform aggregation on sample data!");
			return -1;
		}
		
		return 0;
	}
	
	/**
	 * Insert all IP-addresses into IP-address mapping table
	 * 
	 * @return {@code 0} if successful, {@code -1} otherwise
	 */
	public int insertAllIpAddressMapping() {
		int ipMappingQueryResult = dbConnector.insertAllIpMapping();
		LOGGER.debug("All IP-addresses inserted into IP Mapping table: " + DbConnector.IP_TABLE_NAME + "!");
		
		if (ipMappingQueryResult != 0) {
			LOGGER.error("Unable to perform IP address mapping");
			return -1;
		}
		
		return 0;
	}
	
	/**
	 * Insert all IP-addresses into IP-address mapping table
	 * 
	 * @return {@code 0} if successful, {@code -1} otherwise
	 */
	public int insertAllIpAddressMapping(String[] strings) {
		
		int ipMappingQueryResult = dbConnector.insertAllIpMapping(strings);
		LOGGER.debug("All IP-addresses inserted into IP Mapping table: " + DbConnector.IP_TABLE_NAME + "!");
		
		if (ipMappingQueryResult != 0) {
			LOGGER.error("Unable to perform IP address mapping");
			return -1;
		}
		
		return 0;
	}
	
	/**
	 * Aggregate data from the rawDataTable based on TCP-sessions (unique
	 * combination of {@code <srcIP, destIP, srcPort, destPort>}) and insert
	 * them into the aggregatedDataTable
	 * 
	 * @param rawDataTableName the name of the raw data table
	 * @param aggregatedTableName the name of the aggregated table name
	 * 		
	 * @return {@code 0} if successful, {@code -1} otherwise
	 */
	public int aggregateRawData(String rawDataTableName, String aggregatedTableName) {
		
		int aggregationQueryResult = dbConnector.aggregateRawData(rawDataTableName, aggregatedTableName);
		LOGGER.debug("Aggregated data into: " + aggregatedTableName);
		
		if (aggregationQueryResult != 0) {
			LOGGER.error("Unable to perform aggregation on: " + rawDataTableName);
			return -1;
		}
		
		return 0;
	}
	
}
