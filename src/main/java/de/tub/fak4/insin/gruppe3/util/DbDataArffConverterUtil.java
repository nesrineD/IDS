package de.tub.fak4.insin.gruppe3.util;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instances;
import weka.core.converters.DatabaseSaver;
import de.tub.fak4.insin.gruppe3.model.DbConnector;

/**
 * Generates an ARFF File based on data from Database
 * 
 * @author dima
 */
public class DbDataArffConverterUtil {
	
	/** The logger for this class */
	private static final Logger LOGGER = LoggerFactory.getLogger(DbConnector.class);
	
	/**
	 * Features that will be selected from the aggregated sessions in the
	 * Database
	 */
	private static final String[] FEATURE_ARRAY = { "PL", "FSR", "Duration", "CS", "CNT", "PSH", "reserved", "DF",
			"MF", "Res", "TTL", "TOS", "URG", "ACK", "FIN", "SYN", "RST" };
	
	/** Private constructor to hide the implicit public one */
	private DbDataArffConverterUtil() {
		/*
		 * Nothing
		 */
	}
	
	/**
	 * Writes ARFF File Instances to DB - drops old table.
	 * 
	 * @param arffFile
	 * @param dbConnector
	 * @param tableName Name of the Table that will be created (IF EXISTS OLD
	 *        VALUES WILL BE DROPPED!)
	 * @return returns 0 on success, -1 on failure
	 * @throws Exception
	 */
	public static int writeWekaInstancesToDB(Instances wekaInstances, DbConnector dbConnector, String tableName)
			throws Exception {
		LOGGER.debug("Started Writing ARFF to DB...");
		
		if ((wekaInstances != null) && (wekaInstances.size() > 0)) {
			
			// Execute Query drop old table
			String dataQuery = "DROP TABLE IF EXISTS " + tableName;
			dbConnector.updateDB(dataQuery);
			
			// use WEKA DatabaseSaver to save instances
			wekaInstances.setClassIndex(wekaInstances.numAttributes() - 1);
			DatabaseSaver wekaDbSaver = new DatabaseSaver();
			wekaDbSaver.setUrl(dbConnector.getDbUrl() + dbConnector.getDbSchema());
			wekaDbSaver.setUser("root"); // TODO getUser
			wekaDbSaver.setPassword("root"); // TODO getPassword
			wekaDbSaver.setInstances(wekaInstances);
			wekaDbSaver.setRelationForTableName(false);
			wekaDbSaver.setTableName(tableName);
			
			wekaDbSaver.connectToDatabase();
			wekaDbSaver.writeBatch();
			
			LOGGER.debug("Writing ARFF to DB finished!");
			
		} else {
			LOGGER.debug("data=null -> Could not read ARFF File or File empty.");
			return -1;
		}
		
		return 0;
	}
	
	/**
	 * Returns WEKA {@link Instances} Object from given Database table.
	 * 
	 * @param dbConnector {@link DbConnector} that handles all queries to DB
	 * @param aggregatedTableName the name of the table that stores aggregated
	 *        data
	 * 
	 * @return WEKA {@link Instances} Object
	 * @throws SQLException
	 */
	public static Instances getWekaInstancesFromDb(DbConnector dbConnector, String aggregatedTableName)
			throws SQLException {
		
		if (!dbConnector.isDbConnectionAlive()) {
			LOGGER.error("MYSQL Connection is not Alive.");
			return null;
		}
		
		String queryCommand = "SELECT "
				+ "PL, FSR, Duration, CS, CNT, PSH, reserved, DF, MF, Res, TTL, TOS, URG, ACK, FIN, SYN, RST "
				+ " FROM " + aggregatedTableName + ";";
		ResultSet resultSet = dbConnector.queryDB(queryCommand);
		
		if (resultSet != null) {
			LOGGER.debug("Size of ResultSet: " + resultSet.getFetchSize());
		}
		
		Instances data = getInstance();
		double[] featureValueArray;
		int instancesCount = 0;
		
		// For each TCP-session: append the attributes to the Instances file
		LOGGER.debug("Starting Iteration on ResultSet ");
		while ((resultSet != null) && resultSet.next()) {
			
			// create new entry
			featureValueArray = new double[FEATURE_ARRAY.length];
			
			// The packet counts in the session, required to calculate average
			// values of other features
			double packetCount = Double.parseDouble(resultSet.getString(5));
			
			// Iterate through all feature values
			for (int i = 0; i < FEATURE_ARRAY.length; i++) {
				
				String resultString = "";
				try {
					resultString = resultSet.getString(i + 1);
				} catch (SQLException e) {
					LOGGER.error("Could not getString from " + FEATURE_ARRAY[i] + " Entry in the "
							+ aggregatedTableName + " Table! \n Check the FEATURE_ARRAY !", e);
				}
				
				// starting at 1
				if ((resultString != null) && !resultString.equalsIgnoreCase("null")) {
					
					// The feature-Value before normalization
					double featureValue = Double.parseDouble(resultString);
					
					if (!FEATURE_ARRAY[i].equalsIgnoreCase("FSR") && !FEATURE_ARRAY[i].equalsIgnoreCase("Duration")
							&& !FEATURE_ARRAY[i].equalsIgnoreCase("CNT")) {
						
						featureValue = featureValue / packetCount;
						
					}
					
					// Normalize values using natural logarithmic
					featureValueArray[i] = Math.log(1 + featureValue);
					
				} else {
					LOGGER.debug("Null entry found. Replacing with 0.");
					featureValueArray[i] = Math.log(1 + 0);
				}
			}
			data.add(new DenseInstance(1.0, featureValueArray));
			instancesCount++;
		}
		
		resultSet.close();
		LOGGER.debug("Instances creation done. Total instances created = " + instancesCount);
		
		return data;
	}
	
	/**
	 * Creates the "header" of an ARFF File (defines Attributes)
	 * 
	 * @return Instance with defined Attributes
	 */
	private static Instances getInstance() {
		
		ArrayList<Attribute> atts;
		atts = new ArrayList<Attribute>();
		// create attributes
		for (String feature : FEATURE_ARRAY) {
			// creates NUMERIC attribute
			atts.add(new Attribute(feature));
		}
		return new Instances("Sessions", atts, 0);
		
	}
	
}
