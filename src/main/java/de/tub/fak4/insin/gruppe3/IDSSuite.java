package de.tub.fak4.insin.gruppe3;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.sql.SQLException;

import org.apache.log4j.BasicConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.tub.fak4.insin.gruppe3.classifier.SvmClassifier;
import de.tub.fak4.insin.gruppe3.model.DbConnector;
import de.tub.fak4.insin.gruppe3.preprocessing.DimensionReductor;
import de.tub.fak4.insin.gruppe3.preprocessing.PcapReader;
import de.tub.fak4.insin.gruppe3.preprocessing.TcpSessionAggregator;
import de.tub.fak4.insin.gruppe3.util.ArffFileModifierUtil;
import de.tub.fak4.insin.gruppe3.util.DbDataArffConverterUtil;
import de.tub.fak4.insin.gruppe3.util.KMeansClustererUtil;
import weka.classifiers.functions.LibSVM;
import weka.core.Attribute;
import weka.core.Instances;

/**
 * Main class (currently for debugging purpose)
 * 
 * @author nesrine
 * 		
 */
public class IDSSuite {
	
	/** Logger for this class */
	private static final Logger LOGGER = LoggerFactory.getLogger(SvmClassifier.class);
	/**************** DB RELEVANT INFORMATION ****************/
	private static final String DB_INTERFACE_CLASS_NAME = "com.mysql.jdbc.Driver";
	private static final String DB_URL = "jdbc:mysql://localhost/";
	private static final String DB_USERNAME = "root";
	private static final String DB_PASSWORD = "root";
	private static final String DB_SCHEMA = "intrusionDetection";
	
	/**
	 * Main method
	 * 
	 * @param args Arguments passed on to the main method
	 */
	public static void main(String[] args) {
		
		// Logger purpose
		BasicConfigurator.configure();
		
		// Create a DB connection via the DbConnector
		DbConnector dbConnector = new DbConnector(DB_INTERFACE_CLASS_NAME, DB_URL, DB_USERNAME, DB_PASSWORD, DB_SCHEMA);
		// ===================================================
		// ============== READ PCAP & AGGREGATE ==============
		// ===================================================
		// readPcap(dbConnector);
		// aggregateRawData(dbConnector);
		
		File trainingAggregatedArffFile = new File("resources/TrainAggregatedArff.arff");
		// File trainingDimensionReducedArffFile = new
		// File("resources/TrainDimReducedArff.arff");
		File distancesTrainFile = new File("resources/distancesTrainFile.arff");
		
		File validationAggregatedArffFile = new File("resources/ValidationAggregatedArff.arff");
		// File validationDimensionReducedArffFile = new
		// File("resources/ValidationDimReducedArff.arff");
		File distancesValidationFile = new File("resources/distancesValidationFile.arff");
		
		File evaluationAggregatedArffFile = new File("resources/EvaluationAggregatedArff.arff");
		// File evaluationDimensionReducedArffFile = new
		// File("resources/EvaluationDimReducedArff.arff");
		File distancesEvalFile = new File("resources/distancesEvalFile.arff");
		
		// ================================================
		// ============== SAVE TO ARFF & PCA ==============
		// ================================================
		// saveToArff(dbConnector, trainingAggregatedArffFile,
		// validationAggregatedArffFile, evaluationAggregatedArffFile);
		// performPCA(trainingAggregatedArffFile,trainingDimensionReducedArffFile);
		// performPCA(validationAggregatedArffFile,
		// validationDimensionReducedArffFile);
		
		// ================================================
		// ============== SAVE ARFF TO DB & KMEANS ==============
		// try {
		// ArffFileModifierUtil.saveInstancesToFile(
		// DbDataArffConverterUtil.getWekaInstancesFromDb(dbConnector,
		// DbConnector.TRAIN_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX),
		// trainingAggregatedArffFile);
		// ArffFileModifierUtil.saveInstancesToFile(
		// DbDataArffConverterUtil.getWekaInstancesFromDb(dbConnector,
		// DbConnector.VALIDATION_TABLE_NAME +
		// DbConnector.AGGREGATED_TABLE_SUFFIX),
		// evaluationAggregatedArffFile);
		//
		// } catch (SQLException e) {
		// // TODO Auto-generaiuted catch block
		// e.printStackTrace();
		// }
		// ================================================
		// saveArffToDb(dbConnector, trainingDimensionReducedArffFile);
		// performKMeans(trainingAggregatedArffFile,
		// validationAggregatedArffFile, evaluationAggregatedArffFile,
		// distancesValidationFile, distancesEvalFile);
		// SVM Training
		SvmClassifier svm = null;
		LibSVM oldSvm = null;
		try {
			FileInputStream fileIn = new FileInputStream("resources/modelOne.model");
			ObjectInputStream in = new ObjectInputStream(fileIn);
			oldSvm = (LibSVM) in.readObject();
			in.close();
			if (oldSvm == null) {
				LOGGER.debug("No saved Model found - creating new");
				svm = new SvmClassifier(dbConnector);
				svm.svmTrain(distancesTrainFile);
			} else {
				LOGGER.debug("Loading saved SVM Model");
				svm = new SvmClassifier(dbConnector, oldSvm);
				
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// SVM Validation
		try {
			FileInputStream fileIn = new FileInputStream("resources/modelTWO.model");
			ObjectInputStream in = new ObjectInputStream(fileIn);
			oldSvm = (LibSVM) in.readObject();
			in.close();
			if (oldSvm == null) {
				LOGGER.debug("No saved Validation Model found - creating new Validation Model");
				svm = new SvmClassifier(dbConnector);
				svm.svmValidate(distancesValidationFile);
			} else {
				LOGGER.debug("Loading saved Validation Model");
				svm = new SvmClassifier(dbConnector, oldSvm);
				
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// try {
		// svm.svmValidate(distancesValidationFile);
		// } catch (Exception e) {
		// // TODO Auto-generated catch block
		// e.printStackTrace();
		// }
		// SVM Testing
		try {
			svm.svmTest(distancesEvalFile, 0.10);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	private static void readPcap(DbConnector dbConnector) {
		
		// Read PCAP-Files into DB
		PcapReader pcap = new PcapReader(dbConnector);
		
		// try {
		
		pcap.generateTables();
		
		// Read sample data
		
		// pcap.readPcapFileIntoDB("src/main/resources/Train.pcap",
		// "Train");
		// pcap.readPcapFileIntoDB("src/main/resources/Validation.pcap",
		// "Validation");
		// pcap.readPcapFileIntoDB("src/main/resources/Testing.pcap",
		// "Testing");
		
		String srcPath;
		// String srcPath = "src/main/resources/Training-Week03/";
		// srcPath =
		// "/mnt/data/DARPA/3.week_-_Training_Data_(Attack_Free)/tcpdump/";
		// System.out.println("");
		// System.out.println("======================== TRAIN
		// ========================");
		// System.out.println("");
		// LOGGER.debug("============================================");
		// System.out.print("*** Monday: ");
		// LOGGER.debug(new
		// java.text.SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new
		// Date()));
		// LOGGER.debug("========================);====================");
		// pcap.readPcapFileIntoDB(srcPath +
		// "01.monday.inside.tcpdump","TCP_31_in");
		// pcap.readPcapFileIntoDB(srcPath +
		// "01.monday.outside.tcpdump","TCP_31_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Tuesday: ");
		// LOGGER.debug(new
		// java.text.SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new
		// Date()));
		// LOGGER.debug("============================================");
		// pcap.readPcapFileIntoDB(srcPath + "02.tuesday.inside.tcpdump",
		// "TCP_32_in");
		// pcap.readPcapFileIntoDB(srcPath + "02.tuesday.outside.tcpdump",
		// "TCP_32_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Wednesday: ");
		// LOGGER.debug(new
		// java.text.SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new
		// Date()));
		// LOGGER.debug("============================================");
		// pcap.readPcapFileIntoDB(srcPath + "03.wednesday.inside.tcpdump",
		// "TCP_33_in");
		// pcap.readPcapFileIntoDB(srcPath + "03.wednesday.outside.tcpdump",
		// "TCP_33_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Thursday: ");
		// LOGGER.debug(new
		// java.text.SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new
		// Date()));
		// LOGGER.debug("============================================");
		// pcap.readPcapFileIntoDB(srcPath + "04.thursday.inside.tcpdump",
		// "TCP_34_in");
		// pcap.readPcapFileIntoDB(srcPath + "04.thursday.outside.tcpdump",
		// "TCP_34_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Friday: ");
		// LOGGER.debug(new
		// java.text.SimpleDateFormat("dd.MM.yyyy HH.mm.ss").format(new
		// Date()));
		// LOGGER.debug("============================================");
		// pcap.readPcapFileIntoDB(srcPath + "05.friday.inside.tcpdump",
		// "TCP_35_in");
		// pcap.readPcapFileIntoDB(srcPath + "05.friday.outside.tcpdump",
		// "TCP_35_out");
		
		// System.out.println("");
		// System.out.println("======================== VALIDATE
		// ========================");
		// System.out.println("");
		//
		// // srcPath = "src/main/resources/Validation-Week05/"
		// srcPath = "/mnt/data/DARPA/5.week_-_Validation/";
		// LOGGER.debug("============================================");
		// System.out.print("*** Monday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath +
		// "01.monday.inside.tcpdump","TCP_51_in");
		// pcap.readPcapFileIntoDB(srcPath +
		// "01.monday.outside.tcpdump","TCP_51_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Tuesday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath +
		// "02.tuesday.inside.tcpdump","TCP_52_in");
		// pcap.readPcapFileIntoDB(srcPath +
		// "02.tuesday.outside.tcpdump","TCP_52_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Wednesday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath +
		// "03.wednesday.inside.tcpdump","TCP_53_in");
		// pcap.readPcapFileIntoDB(srcPath +
		// "03.wednesday.outside.tcpdump","TCP_53_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Thursday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath +
		// "04.thursday.inside.tcpdump","TCP_54_in");
		// pcap.readPcapFileIntoDB(srcPath +
		// "04.thursday.outside.tcpdump","TCP_54_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Friday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath +
		// "05.friday.inside.tcpdump","TCP_55_in");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Peform labeling: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// //
		// dbConnector.executeSQLScript("src/main/resources/SQL/4.b_IDS_Sql_AttackIdentificationLabelingWeek5.sql");
		//
		// System.out.println("");
		// System.out.println("======================== TEST
		// ========================");
		// System.out.println("");
		//
		// // srcPath = "src/main/resources/Evaluation-Week04/"
		// srcPath = "/mnt/data/DARPA/4.week_-_Evaluation/";
		// LOGGER.debug("============================================");
		// System.out.print("*** Monday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath + "01.monday.inside.tcpdump",
		// "TCP_41_in");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Tuesday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath + "02.tuesday.inside.tcpdump",
		// "TCP_42_in");
		// pcap.readPcapFileIntoDB(srcPath + "02.tuesday.outside.tcpdump",
		// "TCP_42_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Wednesday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath + "03.wednesday.inside.tcpdump",
		// "TCP_43_in");
		// pcap.readPcapFileIntoDB(srcPath + "03.wednesday.outside.tcpdump",
		// "TCP_43_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Thursday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath + "04.thursday.inside.tcpdump",
		// "TCP_44_in");
		// pcap.readPcapFileIntoDB(srcPath + "04.thursday.outside.tcpdump",
		// "TCP_44_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Friday: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// pcap.readPcapFileIntoDB(srcPath + "05.friday.inside.tcpdump",
		// "TCP_45_in");
		// pcap.readPcapFileIntoDB(srcPath + "05.friday.outside.tcpdump",
		// "TCP_45_out");
		//
		// LOGGER.debug("============================================");
		// System.out.print("*** Peform labeling: ");
		// LOGGER.debug(new java.text.SimpleDateFormat("dd.MM.yyyy
		// HH.mm.ss").format(new Date()));
		// LOGGER.debug("==============================================");
		// //
		// dbConnector.executeSQLScript("src/main/resources/SQL/4.a_IDS_Sql_AttackIdentificationLabelingWeek4.sql");
		
		// } catch (PcapNativeException | NotOpenException e) {
		// e.printStackTrace();
		// }
	}
	
	private static void aggregateRawData(DbConnector dbConnector) {
		// Aggregate Raw data into TCP sessions
		
		TcpSessionAggregator aggregator = new TcpSessionAggregator(dbConnector);
		// aggregator.insertAllIpAddressMapping();
		// LOGGER.debug("insertAllIpAddressMapping started...");
		// aggregator.insertAllIpAddressMapping(
		// new String[] { "TCP_31_in", "TCP_31_out", "TCP_32_in", "TCP_32_out",
		// "TCP_33_in", "TCP_33_out",
		// "TCP_34_in", "TCP_34_out", "TCP_35_in", "TCP_35_out", "TCP_41_in",
		// "TCP_42_out", "TCP_43_in",
		// "TCP_43_out", "TCP_44_in", "TCP_44_out", "TCP_45_in", "TCP_45_out",
		// "TCP_51_in", "TCP_51_out",
		// "TCP_52_in", "TCP_52_out", "TCP_53_in", "TCP_53_out", "TCP_54_in",
		// "TCP_54_out", "TCP_55_in" });
		
		// Aggregate sample data
		// aggregator.aggregateRawData();
		
		// Aggregate DARPA'99 datasets
		LOGGER.debug("aggregation started...");
		aggregator.aggregateRawData("TCP_31_in", "Train_mappedTable");
		aggregator.aggregateRawData("TCP_31_out", "Train_mappedTable");
		aggregator.aggregateRawData("TCP_32_in", "Train_mappedTable");
		aggregator.aggregateRawData("TCP_32_out", "Train_mappedTable");
		aggregator.aggregateRawData("TCP_33_in", "Train_mappedTable");
		aggregator.aggregateRawData("TCP_33_out", "Train_mappedTable");
		aggregator.aggregateRawData("TCP_34_in", "Train_mappedTable");
		aggregator.aggregateRawData("TCP_34_out", "Train_mappedTable");
		aggregator.aggregateRawData("TCP_35_in", "Train_mappedTable");
		aggregator.aggregateRawData("TCP_35_out", "Train_mappedTable");
		
		aggregator.aggregateRawData("TCP_41_in", "Validation_mappedTable");
		aggregator.aggregateRawData("TCP_42_out", "Validation_mappedTable");
		aggregator.aggregateRawData("TCP_43_in", "Validation_mappedTable");
		aggregator.aggregateRawData("TCP_43_out", "Validation_mappedTable");
		aggregator.aggregateRawData("TCP_44_in", "Validation_mappedTable");
		aggregator.aggregateRawData("TCP_44_out", "Validation_mappedTable");
		aggregator.aggregateRawData("TCP_45_in", "Validation_mappedTable");
		aggregator.aggregateRawData("TCP_45_out", "Validation_mappedTable");
		
		aggregator.aggregateRawData("TCP_51_in", "Testing_mappedTable");
		aggregator.aggregateRawData("TCP_51_out", "Testing_mappedTable");
		aggregator.aggregateRawData("TCP_52_in", "Testing_mappedTable");
		aggregator.aggregateRawData("TCP_52_out", "Testing_mappedTable");
		aggregator.aggregateRawData("TCP_53_in", "Testing_mappedTable");
		aggregator.aggregateRawData("TCP_53_out", "Testing_mappedTable");
		aggregator.aggregateRawData("TCP_54_in", "Testing_mappedTable");
		aggregator.aggregateRawData("TCP_54_out", "Testing_mappedTable");
		aggregator.aggregateRawData("TCP_55_in", "Testing_mappedTable");
		LOGGER.debug("aggregation finished...");
		
	}
	
	private static void saveToArff(DbConnector dbConnector, File trainingAggregatedArffFile,
			File validationAggregatedArffFile, File evaluationAggregatedArffFile) {
			
		// Save to ARFF File
		try {
			ArffFileModifierUtil.saveInstancesToFile(
					DbDataArffConverterUtil.getWekaInstancesFromDb(dbConnector,
							DbConnector.TRAIN_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX),
					trainingAggregatedArffFile);
					
			ArffFileModifierUtil.saveInstancesToFile(
					DbDataArffConverterUtil.getWekaInstancesFromDb(dbConnector,
							DbConnector.VALIDATION_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX),
					validationAggregatedArffFile);
					
			ArffFileModifierUtil.saveInstancesToFile(
					DbDataArffConverterUtil.getWekaInstancesFromDb(dbConnector,
							DbConnector.TESTING_TABLE_NAME + DbConnector.AGGREGATED_TABLE_SUFFIX),
					evaluationAggregatedArffFile);
					
		} catch (SQLException e1) {
			e1.printStackTrace();
		}
		
	}
	
	private static void performPCA(File trainingAggregatedArffFile, File trainingDimensionReducedArffFile) {
		// Read from ARFF File & perform PCA
		DimensionReductor pca;
		
		try {
			pca = new DimensionReductor(trainingAggregatedArffFile);
			Instances dimensionReducedInstances = pca.performPca();
			
			// // TODO Test
			// Instances reduced2 =
			// pca.performPca(ArffFileModifierUtil.readIntancesFromFile(trainingAggregatedArffFile));
			
			for (int i = 0; i < dimensionReducedInstances.numAttributes(); i++) {
				Attribute att = dimensionReducedInstances.attribute(i);
			}
			
			ArffFileModifierUtil.saveInstancesToFile(dimensionReducedInstances, trainingDimensionReducedArffFile);
			
			// // TODO Test
			// ArffFileModifierUtil.saveInstancesToFile(reduced2,
			// new File(trainingDimensionReducedArffFile.getAbsolutePath() +
			// "copy"));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	private static void saveArffToDb(DbConnector dbConnector, File dimensionReducedArffFile) {
		
		// Write ARFF to DB
		try {
			Instances dimensionReducedInstances = ArffFileModifierUtil.readIntancesFromFile(dimensionReducedArffFile);
			DbDataArffConverterUtil.writeWekaInstancesToDB(dimensionReducedInstances, dbConnector,
					DbConnector.TRAIN_TABLE_NAME + DbConnector.FEATURE_TABLE_SUFFIX);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	private static void performKMeans(File trainingDimensionReducedArffFile, File validationDimensionReducedArffFile,
			File evaluationDimensionReducedArffFile, File distancesValidationFile, File distancesEvalFile) {
			
		// Perform K-Means
		try {
			
			File distancesTrainFile = KMeansClustererUtil.createKMeansClusters(3, trainingDimensionReducedArffFile,
					"distancesTrainFile.arff");
					
			Instances centers = ArffFileModifierUtil.readIntancesFromFile(new File("resources/centers.arff"));
			
			// ========================================================================================
			LOGGER.debug("compute");
			Instances distancesValidation = KMeansClustererUtil.computeDistances(
					ArffFileModifierUtil.readIntancesFromFile(validationDimensionReducedArffFile), centers, 3);
					
			ArffFileModifierUtil.saveInstancesToFile(distancesValidation, distancesValidationFile);
			
			// ========================================================================================
			LOGGER.debug("compute 2");
			Instances distancesEval = KMeansClustererUtil.computeDistances(
					ArffFileModifierUtil.readIntancesFromFile(evaluationDimensionReducedArffFile), centers, 3);
					
			ArffFileModifierUtil.saveInstancesToFile(distancesEval, distancesEvalFile);
			//
			// ========================================================================================
			
			// KMeansClustererUtil.buildSVMClassifier(distancesTrainFile,
			// distancesEvalFile);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
