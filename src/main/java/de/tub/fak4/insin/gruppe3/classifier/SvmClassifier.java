package de.tub.fak4.insin.gruppe3.classifier;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.sql.ResultSet;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.tub.fak4.insin.gruppe3.model.DbConnector;
import de.tub.fak4.insin.gruppe3.util.ArffFileModifierUtil;
import weka.classifiers.functions.LibSVM;
import weka.core.Attribute;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SelectedTag;

/**
 * Performs one class SVM classification
 *
 * @author nesrine
 */
public class SvmClassifier {
	
	/** Logger for this class */
	private static final Logger LOGGER = LoggerFactory.getLogger(SvmClassifier.class);
	/** The (one class) SVM classifier */
	private final LibSVM libSvmClassifier;
	/** The DB connector to handle all DB-queries */
	private DbConnector dbConnector;
	
	/** The path where the YAML file output will be saved */
	private static final String YAML_ATTACK_FILE_PATH = "Group03Output";
	/** The path where the YAML test statistics file will be saved */
	private static final String YAML_STATISTICS_FILE_PATH = "Group03Statistics";
	
	/**
	 * Constructor
	 *
	 * @param dbConnector
	 */
	public SvmClassifier(DbConnector dbConnector) {
		if (dbConnector == null) {
			LOGGER.error("Invalid DB-Connector! SVM-Classifier will not work properly!");
		} else {
			this.dbConnector = dbConnector;
		}
		
		libSvmClassifier = new LibSVM();
		setUp(libSvmClassifier);
	}
	
	public SvmClassifier(DbConnector dbConnector, LibSVM libSvmClassifier) {
		if (dbConnector == null) {
			LOGGER.error("Invalid DB-Connector! SVM-Classifier will not work properly!");
		} else {
			this.dbConnector = dbConnector;
		}
		
		this.libSvmClassifier = libSvmClassifier;
		setUp(libSvmClassifier);
	}
	
	/**
	 * Trains the one class SVM
	 *
	 * @param trainFile the training data set in ARFF-{@link File}
	 * 		
	 * @throws Exception
	 */
	public void svmTrain(File trainingArffFile)
			throws Exception {
			
		if ((trainingArffFile == null) || !trainingArffFile.exists() || !trainingArffFile.canRead()) {
			LOGGER.error("Invalid training ARFF file! Unable to train SVM!");
			return;
		}
		
		Instances data = ArffFileModifierUtil.readIntancesFromFile(trainingArffFile);
		
		// prepare training data set - add class attribute
		insertClassField(data, true);
		
		ArffFileModifierUtil.saveInstancesToFile(data, new File("resources/TrainInstances.arff"));
		LOGGER.debug("Trying to Build SVM on " + data.size() + " Instances");
		LOGGER.debug("Number of Attributes: " + data.numAttributes());
		
		for (int i = 0; i < data.numAttributes(); i++) {
			LOGGER.debug("Name of " + i + " Attribute: " + data.attribute(i).name());
		}
		
		String fristInst = data.get(0).value(0) + " " + data.get(0).value(1) + " " + data.get(0).value(2) + " "
				+ data.get(0).value(3);
		LOGGER.debug("First Instance: " + fristInst);
		
		LOGGER.debug("Nu wert:" + libSvmClassifier.getNu());
		LOGGER.debug("Building SVM classifier...");
		libSvmClassifier.buildClassifier(data);
		LOGGER.debug("SVM classifier built.");
		
		LOGGER.debug("Saving SVM model...");
		saveSVMModel(libSvmClassifier, "resources/modelOne.model");
		LOGGER.debug("SVM model saved.");
	}
	
	/**
	 * Performs the anomaly prediction
	 *
	 * @param newModelFeature the new model obtained after the updating
	 * @param testFeature the path to the test features
	 * @throws Exception
	 */
	public void classifyDataSet(File testingArffFile)
			throws Exception {
			
		Instances testInstance = ArffFileModifierUtil.readIntancesFromFile(testingArffFile);
		
		if (testInstance.classIndex() == -1) {
			testInstance.setClassIndex(testInstance.numAttributes() - 1);
		}
		
		// predict labels of testing data
		for (int i = 0; i < testInstance.numInstances(); i++) {
			
			Instance instance = testInstance.instance(i);
			
			LOGGER.debug(testInstance.classAttribute().value((int) instance.classValue()) + " -- ");
			
			double result = libSvmClassifier.classifyInstance(instance);
			
			LOGGER.debug(testInstance.classAttribute().value((int) result));
		}
	}
	
	/**
	 * Does the model updating
	 *
	 * @param validFile the validation file
	 * @throws Exception
	 */
	public void svmValidate(File validationArffFile)
			throws Exception {
			
		Instances validData = ArffFileModifierUtil.readIntancesFromFile(validationArffFile);
		LOGGER.debug("Validation Dataset size: " + validData.size());
		
		// prepare training data set - add class attribute
		insertClassField(validData, false);
		
		Instances newModelInstances = new Instances(validData, 0);
		double th = 0;
		for (int i = 0; i < validData.numInstances(); i++) {
			if ((double) (i + 1) / (double) validData.numInstances() > th) {
				LOGGER.debug(LocalDateTime.now() + "Validation Progress " + th + "%");
				th += 0.05; // <- display every 5% progress
			}
			double result = libSvmClassifier.classifyInstance(validData.instance(i));
			validData.instance(i).setClassValue(result);
			
			// test normal instances that they are truly normal (labeling)
			if (validData.instance(i).value(3) == 0.0) {
				// since we dont have any labeling for the validation-set just
				// insert normal data points.
				newModelInstances.add(validData.instance(i));
				// ResultSet Session =
				// queryDbForSourceIpAndCategory("Validation_mappedTable", i);
				//
				// if ((Session != null) && Session.next()) {
				// if (Session.getString(5).equals("0")) {
				// // LOGGER.debug("Data was correctly labeled!");
				// newModelInstances.add(validData.instance(i));
				// } else {
				// // LOGGER.debug("Data was incorrectly labeled!");
				// }
				// } else {
				// LOGGER.error("ResultSet of given Session is null!");
				// }
			}
		}
		
		if ((newModelInstances != null) && (newModelInstances.size() > 0)) {
			
			ArffFileModifierUtil.saveInstancesToFile(newModelInstances, new File("resources/newModelInstances.arff"));
			libSvmClassifier.buildClassifier(newModelInstances);
			saveSVMModel(libSvmClassifier, "resources/modelTWO.model");
			
			LOGGER.debug("New Validation Model was created! Instances size: " + newModelInstances.size());
			
		} else {
			LOGGER.error("No model was created - new model has 0 instances");
		}
		
	}
	
	/**
	 * 
	 * @param EvalFile
	 * @param amount % of Data Set to be evaluated
	 * @throws Exception
	 */
	
	public void svmTest(File EvalFile, double amount)
			throws Exception {
			
		int truePositives = 0;
		int trueNegatives = 0;
		int falsePositives = 0;
		int falseNegatives = 0;
		
		Instances testData = ArffFileModifierUtil.readIntancesFromFile(EvalFile);
		if ((testData == null) || (testData.size() < 1)) {
			LOGGER.error("testData in " + EvalFile.getAbsolutePath() + " is null");
			return;
		}
		
		LOGGER.debug("Test Dataset size: " + testData.size());
		
		// prepare training data set - add class attribute
		insertClassField(testData, false);
		HashSet<Integer> attacks = new HashSet<Integer>();
		
		// prepare the yaml writer
		File yamlAttackFile = new File(YAML_ATTACK_FILE_PATH + System.currentTimeMillis() + ".yaml");
		yamlAttackFile.createNewFile();
		
		File yamlStatisticsFile = new File(YAML_STATISTICS_FILE_PATH + System.currentTimeMillis() + ".yaml");
		yamlStatisticsFile.createNewFile();
		
		YamlWriter yamlWriter = new YamlWriter(yamlAttackFile);
		
		LOGGER.debug("Classifying instances...");
		double th = 0;
		for (int i = 0; i < testData.numInstances(); i++) {
			// required amount of Data analysed.
			if ((double) (i + 1) / (double) testData.numInstances() > amount)
				break;
			if ((double) (i + 1) / (double) testData.numInstances() > th) {
				LOGGER.debug(LocalDateTime.now() + "Classification Progress " + th + "%");
				th += 0.05; // <- display every 5% progress
			}
			
			double result = libSvmClassifier.classifyInstance(testData.instance(i));
			testData.instance(i).setClassValue(result);
			
			ResultSet tcpSession = queryDbForSourceIpAndCategory("Testing_mappedTable", i);
			
			if (!((tcpSession != null) && tcpSession.next())) {
				LOGGER.error("ResultSet of given Session is null!");
				continue;
			}
			
			boolean isSessionLabeledAsNormal = (testData.instance(i).value(3) == 0.0);
			
			// Save Attack Index
			if (!isSessionLabeledAsNormal) {
				attacks.add(i);
				
				yamlWriter.addAttackToList(new ArrayList<>(), "An anomaly was detected!", tcpSession.getString(1),
						tcpSession.getString(3), tcpSession.getString(2), tcpSession.getString(4), "Anomaly",
						tcpSession.getString(6), "N/A");
			}
			if (!tcpSession.getString(5).equals("0"))
				LOGGER.debug("Session: " + tcpSession.getString(1) + " " + tcpSession.getString(2) + " "
						+ tcpSession.getString(3) + " " + tcpSession.getString(4) + " " + tcpSession.getString(5) + " "
						+ tcpSession.getString(6));
			// Session is actually NORMAL
			if (tcpSession.getString(5).equals("0")) {
				
				// classified as normal
				if (isSessionLabeledAsNormal) {
					trueNegatives++;
				}
				// classified as attack
				else {
					falsePositives++;
				}
			}
			
			// Session is actually ATTACK
			else {
				
				// classified as normal
				if (isSessionLabeledAsNormal) {
					falseNegatives++;
					LOGGER.debug("Attack was not detected... FalseNegatives:" + falseNegatives);
				}
				// classified as attack
				else {
					truePositives++;
					LOGGER.debug("Attack was  detected! TruePositives:" + truePositives);
				}
			}
			
		}
		
		LOGGER.debug("Instances classification finished. " + amount + "% of Data was Analyzed. Total of "
				+ (truePositives + trueNegatives + falsePositives + falseNegatives) + " Sessions analyzed.");
				
		yamlWriter.saveTestStatistics(truePositives, trueNegatives, falsePositives, falseNegatives, attacks,
				yamlStatisticsFile);
				
		LOGGER.debug("YAML Output: " + yamlWriter.saveToYamlFile());
		
	}
	
	public void svmTest(File evaluationArffFile)
			throws Exception {
		svmTest(evaluationArffFile, 1.0);
	}
	
	/**
	 * Inserts new class Field into Instances
	 *
	 * @param testData
	 * @param setToNormal if true sets new field to "normal" value
	 */
	private void insertClassField(Instances testData, boolean setToNormal) {
		ArrayList<String> attributeValues = new ArrayList<String>();
		Attribute attr;
		attributeValues.add("normal");
		attr = new Attribute("class", attributeValues);
		testData.insertAttributeAt(attr, testData.numAttributes());
		
		if (testData.classIndex() == -1) {
			testData.setClassIndex(testData.numAttributes() - 1);
		}
		if (setToNormal) {
			for (Instance inst : testData) {
				inst.setValue(3, "normal");
			}
		}
		
	}
	
	/**
	 * Sets up One-Class-SVM with settings taken from the Master Thesis
	 * <p>
	 * <li>-s 2 (one-class SVM)</li>
	 * <li>-t 2 (radial basis kernel)</li>
	 * <li>-d 3 (degree = 3)</li>
	 * <li>-n 0.1 (nu = 0.1)</li>
	 * <li>-g 0.125 (gamma = 0.125)</li>
	 * <p>
	 *
	 * @param libSvm the one-class SVM classifier
	 */
	private void setUp(LibSVM libSvm) {
		try {
			libSvm.setNu(0.1);
			libSvm.setGamma(0.125);
			libSvm.setDegree(3);
			libSvm.setSVMType(new SelectedTag(LibSVM.SVMTYPE_ONE_CLASS_SVM, LibSVM.TAGS_SVMTYPE));
			// libSvm.setOptions(new String[] { "-s 2", "-t 2", "-d 3",
			// "-n 0.1", "-g 0.125" });
		} catch (Exception e) {
			LOGGER.error("Could not set Options for One-Class-SVM: " + libSvm, e);
		}
	}
	
	/**
	 * Query the DB to retrieve the row that contains the sourceIP, destIP,
	 * sourcePort, destPort, and the category
	 *
	 * @param aggregatedDataTableName the name of the table that holds the
	 *        aggregated data (TCP session)
	 * @param rowPosition the index (position) of the row (<b>starts at
	 *        {@code 0}</b>)
	 * 		
	 * @return the {@link ResultSet} that contains the DB-query-Result
	 */
	private ResultSet queryDbForSourceIpAndCategory(String aggregatedDataTableName, int rowPosition) {
		
		String sqlQueryCommand = "SELECT " + //
				"IpMapSrc.IP AS sourceIP," + //
				" IpMapDest.IP AS destinationIP," + //
				" aggregatedTable.srcPort ," + //
				" aggregatedTable.destPort," + //
				" aggregatedTable.Category," + //
				" aggregatedTable.PacketTime" + //
				" FROM " + aggregatedDataTableName + " AS aggregatedTable" + //
				" LEFT JOIN " + DbConnector.IP_TABLE_NAME + " AS IpMapSrc ON " + "aggregatedTable.SrcIp="
				+ "IpMapSrc.ID " + " LEFT JOIN (Select * from " + DbConnector.IP_TABLE_NAME + ") as IpMapDest ON "
				+ "aggregatedTable.destIP=IpMapDest.ID " + "LIMIT " + rowPosition + ", 1;";
				
		return dbConnector.queryDB(sqlQueryCommand);
	}
	
	/**
	 * Saves the LibSVM model in the specific path
	 *
	 * @param model LibSVM model
	 * @param path the path of the file to save t
	 * @throws IOException
	 */
	private void saveSVMModel(LibSVM model, String path)
			throws IOException {
		FileOutputStream fileOut = new FileOutputStream(path);
		ObjectOutputStream out = new ObjectOutputStream(fileOut);
		out.writeObject(model);
		out.close();
	}
	
}
