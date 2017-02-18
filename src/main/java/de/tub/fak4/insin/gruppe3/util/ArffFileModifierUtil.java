package de.tub.fak4.insin.gruppe3.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import weka.core.Instances;
import weka.core.converters.ArffSaver;

/**
 * Provides various methods to modify an ARFF file such as reading WEKA
 * {@link Instances}, or cutting {@link Instances} (based on dimension reduction
 * from PCA) from the given ARFF file
 * 
 * @author alwin
 * 
 */
public class ArffFileModifierUtil {
	
	/** The logger for this class */
	private static final Logger LOGGER = LoggerFactory.getLogger(ArffFileModifierUtil.class);
	
	/** Private constructor to hide the implicit public one */
	private ArffFileModifierUtil() {
		/*
		 * Nothing
		 */
	}
	
	/**
	 * Saves Instances Object to ARFF File Format
	 * 
	 * @param wekaInstances
	 * @param arffFile
	 */
	public static File saveInstancesToFile(Instances wekaInstances, File arffFile) {
		ArffSaver saver = new ArffSaver();
		if (wekaInstances == null) {
			LOGGER.error("Instances are null!");
			return null;
		}
		saver.setInstances(wekaInstances);
		
		try {
			saver.setFile(arffFile);
			saver.writeBatch();
		} catch (IOException e) {
			LOGGER.error("ERROR Saving ARFF. Could not save to " + arffFile.getAbsolutePath()
					+ "\n Check your File Path?");
			e.printStackTrace();
		}
		
		LOGGER.debug("Writing ARFF File to " + arffFile.getAbsolutePath());
		return arffFile;
	}
	
	/**
	 * Reads an ARFF File and Returns {@link Instances} Object
	 * 
	 * @param arffFile
	 * @return the WEKA {@link Instances} read from the given ARFF file
	 */
	public static Instances readIntancesFromFile(File arffFile) {
		
		try (BufferedReader reader = new BufferedReader(new FileReader(arffFile))) {
			
			Instances data = null;
			try {
				data = new Instances(reader);
			} catch (IOException e) {
				LOGGER.error("Could not read Instances from ARFF File " + arffFile.getAbsolutePath() + " Wrong format?");
				e.printStackTrace();
			} finally {
				try {
					reader.close();
				} catch (IOException e) {
					LOGGER.error("IO-Exception while attempting to close the BufferedReader!");
				}
			}
			
			return data;
			
		} catch (FileNotFoundException e) {
			LOGGER.error("The ARFF-file: " + arffFile.getAbsolutePath() + " can not be found!");
		} catch (IOException e1) {
			LOGGER.error("Unable to attach Buffered reader to the ARFF file: " + arffFile.getAbsolutePath());
		}
		
		return null;
	}
}
