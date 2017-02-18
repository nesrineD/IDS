package de.tub.fak4.insin.gruppe3.preprocessing;

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import weka.attributeSelection.AttributeSelection;
import weka.attributeSelection.PrincipalComponents;
import weka.attributeSelection.Ranker;
import weka.core.Instances;
import de.tub.fak4.insin.gruppe3.util.ArffFileModifierUtil;

/**
 * Performs Principle Component Analysis (PCA) to reduce dimension of the data
 * while maintaining the 'completeness' of the information that can be retrieved
 * from the data
 *
 * @author alwin
 *
 */
public class DimensionReductor {
	
	/** The logger for this class */
	private static final Logger LOGGER = LoggerFactory.getLogger(DimensionReductor.class);
	
	/** PCA responsible for dimension reduction process */
	private final PrincipalComponents principleComponentAnalysis;
	/** The amount of variance in the data that should be covered by PCA */
	private static final double varianceCoveredByPca = 0.996;

	/** The WEKA {@link Instances} read from the given ARFF-{@link File} */
	private Instances wekaInstances;
	
	/**
	 * Constructor
	 *
	 * @param arffFile the {@link File} containing ARFF-data (in form of WEKA
	 *        {@link Instances})
	 */
	public DimensionReductor(File arffFile) {
		
		if ((arffFile != null) && arffFile.exists() && arffFile.canRead()) {
			wekaInstances = ArffFileModifierUtil.readIntancesFromFile(arffFile);
			LOGGER.debug("Loaded the WEKA-Instances containing: " + wekaInstances.numInstances()
					+ " instances from ARFF-file: " + arffFile.getAbsolutePath());
		}
		
		principleComponentAnalysis = new PrincipalComponents();
		principleComponentAnalysis.setVarianceCovered(varianceCoveredByPca);
	}
	
	/**
	 * Performs the principle component analysis on the given ARFF-{@link File}
	 *
	 * @return the WEKA {@link Instances}, whose dimension has been reduced by
	 *         the PCA process
	 *
	 * @throws Exception if the principle component analysis process fails
	 */
	public Instances performPca()
			throws Exception {
		
		// ================ Standard WEKA PCA-Workflow ================
		
		AttributeSelection selector = new AttributeSelection();
		Ranker ranker = new Ranker();
		
		selector.setEvaluator(principleComponentAnalysis);
		selector.setSearch(ranker);
		
		selector.SelectAttributes(wekaInstances);
		Instances reducedDImensionWekaInstances = selector.reduceDimensionality(wekaInstances);
		
		// ============================================================
		
		return reducedDImensionWekaInstances;
	}
	
}
