package de.tub.fak4.insin.gruppe3.classifier;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

/**
 * Deals with writing and reading YAML file
 *
 * @author alwin
 *
 */
public class YamlWriter {
	
	/** Logger for this utility class */
	private static final Logger LOGGER = LoggerFactory.getLogger(YamlWriter.class);

	/** The list of attacks in Map format to be saved into an Yaml-file */
	private List<Map<String, Object>> attackList;
	/** The file to save the attack list in Yaml format */
	private File yamlFile;

	/**
	 * Constructor
	 */
	public YamlWriter(File yamlFileToSaveAttackList) {
		attackList = new LinkedList<>();
		yamlFile = yamlFileToSaveAttackList;
		LOGGER.debug(this.getClass().getSimpleName() + " will save the attack list unto: "
				+ yamlFileToSaveAttackList.getAbsolutePath());
	}
	
	/**
	 * Adds information of a (possibly) detected attack into the attackList to
	 * be saved into Yaml {@link File}.
	 *
	 * @param additionalPackets additional (related) Packets to the detected
	 *        attack
	 * @param description description of the attack
	 * @param attackerIp the IP-address of the attacker
	 * @param attackerPort the port number of the attacker
	 * @param victimIp the IP-address of the victim
	 * @param victimPort the port number of the victim
	 * @param name the name of the detected attack (e.g. ARP-Spoofing, DDoS)
	 * @param packetTime the time-stamp of the packet
	 * @param score the confidence of the attack detection
	 *
	 * @return {@code true} if the attack is added to the list, {@code false}
	 *         otherwise
	 */
	public boolean addAttackToList(Object additionalPackets, Object description, Object attackerIp,
			Object attackerPort, Object victimIp, Object victimPort, Object name, Object packetTime, Object score) {

		boolean isSuccessful = false;
		
		// Since packetTime is required field...
		if (packetTime != null) {
			
			Map<String, Object> detectedAttack = new HashMap<>();

			Map<String, Object> extraMap = new HashMap<>();
			extraMap.put("attackerIP", attackerIp);
			extraMap.put("attackerPort", attackerPort);
			extraMap.put("victimIP", victimIp);
			extraMap.put("victimPort", victimPort);
			
			detectedAttack.put("additionalPackets", new ArrayList<String>());
			detectedAttack.put("description", description);
			detectedAttack.put("extra", extraMap);
			detectedAttack.put("group", "Group3");
			detectedAttack.put("name", name);
			detectedAttack.put("packet", packetTime);
			detectedAttack.put("score", score);

			attackList.add(detectedAttack);
			
			isSuccessful = true;
		}

		return isSuccessful;
	}

	/**
	 * Save the (detected) attack list to a {@link File} in Yaml format
	 *
	 * @return the {@link File} where the attack list has been saved
	 * @throws IOException if the file exists but is a directory rather than a
	 *         regular file, does not exist but cannot be created, or cannot be
	 *         opened for any other reason
	 */
	public File saveToYamlFile()
			throws IOException {

		if ((yamlFile != null) && yamlFile.canWrite() && (attackList != null) && !attackList.isEmpty()) {

			LOGGER.debug("Saving the attack list to: " + yamlFile.getAbsolutePath());
			FileWriter fileWriter = new FileWriter(yamlFile);
			
			DumperOptions yamlDumperOptions = new DumperOptions();
			yamlDumperOptions.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
			yamlDumperOptions.setIndent(4);
			
			Yaml yaml = new Yaml(yamlDumperOptions);
			yaml.dump(attackList, fileWriter);

			LOGGER.debug("Attack list has been saved to: " + yamlFile.getAbsolutePath());

		} else {
			LOGGER.error("Unable to save the attack list unto file: " + yamlFile);
		}

		return yamlFile;
	}

	/**
	 * Method that saves Test Results
	 *
	 * @param truePositives True Positives
	 * @param trueNegatives True Negatives
	 * @param falsePositives False Positives
	 * @param falseNegatives False Negatives
	 * @param attacks Indexes of Sessions that were classified as Attacks.
	 *
	 * @throws IOException if the file exists but is a directory rather than a
	 *         regular file, does not exist but cannot be created, or cannot be
	 *         opened for any other reason
	 */
	public File saveTestStatistics(int truePositives, int trueNegatives, int falsePositives, int falseNegatives,
			HashSet<Integer> attacks, File testStatisticsFile)
					throws IOException {
		
		if ((testStatisticsFile != null) && testStatisticsFile.canWrite()) {
			LOGGER.debug("Saving test statistics...\n\n");
			
			LOGGER.debug("True Positives: " + truePositives);
			LOGGER.debug("True Negatives: " + trueNegatives);
			LOGGER.debug("False Positives: " + falsePositives);
			LOGGER.debug("False Negatives: " + falseNegatives);
			LOGGER.debug("Precision:" + ((double) truePositives / (double) (truePositives + falsePositives)));
			LOGGER.debug("Recall:" + ((double) truePositives / (double) (truePositives + falseNegatives)));
			LOGGER.debug("Number of Attacks found: " + attacks.size() + "\n\n");
			
			Map<String, Object> statistics = new HashMap<>();
			statistics.put("True Positives", truePositives);
			statistics.put("True Negatives", trueNegatives);
			statistics.put("False Positives", falsePositives);
			statistics.put("False Negatives", falseNegatives);
			statistics.put("Precision", ((double) truePositives / (double) (truePositives + falsePositives)));
			statistics.put("Recall", ((double) truePositives / (double) (truePositives + falseNegatives)));
			statistics.put("Number of detected attacks", attacks.size());
			
			FileWriter fileWriter = new FileWriter(testStatisticsFile);
			
			DumperOptions yamlDumperOptions = new DumperOptions();
			yamlDumperOptions.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
			yamlDumperOptions.setIndent(4);
			
			Yaml yaml = new Yaml(yamlDumperOptions);
			yaml.dump(statistics, fileWriter);
			
			LOGGER.debug("Test statistics have been saved to: " + testStatisticsFile);
		} else {
			LOGGER.error("Unable to save the test statistics unto file: " + testStatisticsFile);
		}

		return testStatisticsFile;
	}
}
