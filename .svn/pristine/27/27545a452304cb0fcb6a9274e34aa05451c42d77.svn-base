package de.tub.fak4.insin.gruppe3.util;

import java.io.File;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import weka.clusterers.SimpleKMeans;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;

/**
 * implements K-Means clustering from Weka
 * 
 * @author Evgeny
 */
public class KMeansClustererUtil {
	
	/** Logger for this class */
	private static final Logger LOGGER = LoggerFactory.getLogger(KMeansClustererUtil.class);
	
	/** Private constructor to hide the public implicit one */
	private KMeansClustererUtil() {
		/*
		 * Nothing
		 */
	}
	
	/**
	 * 
	 * create specified number of clusters
	 * 
	 * @param numClusters - number of clusters
	 * @param arffFile - link to a arff file
	 * @return
	 * @throws Exception if number of clusters is negative
	 */
	public static File createKMeansClusters(int numClusters, File arffFile, String targetARFF)
			throws Exception {
		
		LOGGER.debug("Performing k-means clustering for: " + numClusters + " clusters using: "
				+ arffFile.getAbsolutePath());
		
		SimpleKMeans kmeans = new SimpleKMeans();
		
		// do multiple iterations with different random initial centers
		kmeans.setSeed(10);
		kmeans.setPreserveInstancesOrder(true);
		kmeans.setNumClusters(numClusters);
		
		Instances wekaInstances = ArffFileModifierUtil.readIntancesFromFile(arffFile);
		
		kmeans.buildClusterer(wekaInstances);
		
		// LOGGER.debug("Cluster centroids:");
		// LOGGER.debug("\t" + kmeans.getClusterCentroids());
		
		Instances distInstances = computeDistances(wekaInstances, kmeans.getClusterCentroids(), numClusters);
		
		ArffFileModifierUtil.saveInstancesToFile(kmeans.getClusterCentroids(), new File("resources/centers.arff"));
		
		File returnARFF = new File("resources/" + targetARFF);
		ArffFileModifierUtil.saveInstancesToFile(distInstances, returnARFF);
		
		LOGGER.debug("K-means clustering for: " + numClusters + " clusters using: " + arffFile.getAbsolutePath()
				+ " is completed");
		
		return returnARFF;
	}
	
	/**
	 * 
	 * Compute euclidian distance
	 * 
	 * @param instances
	 * @param centerInstances
	 * @return distanceInstances
	 */
	public static Instances computeDistances(Instances instances, Instances centerInstances, int numClusters) {
		ArrayList<Attribute> attrList = new ArrayList<Attribute>();
		for (int j = 0; j < numClusters; j++) {
			attrList.add(new Attribute("distance" + j));
		}
		
		Instances distInstances = new Instances("ClusterDistance", attrList, 0);
		Instance newInstance = new DenseInstance(3);
		double distanceToCluster0, distanceToCluster1, distanceToCluster2;
		// LOGGER.debug("" + instances);
		// LOGGER.debug("=============================");
		// LOGGER.debug("=============================");
		// LOGGER.debug("" + centerInstances);
		for (Instance inst : instances) {
			distanceToCluster0 = 0;
			distanceToCluster1 = 0;
			distanceToCluster2 = 0;
			
			for (int j = 0; j < instances.numAttributes(); j++) {
				distanceToCluster0 += Math.sqrt(Math.pow(inst.value(j) - centerInstances.instance(0).value(j), 2));
				distanceToCluster1 += Math.sqrt(Math.pow(inst.value(j) - centerInstances.instance(1).value(j), 2));
				distanceToCluster2 += Math.sqrt(Math.pow(inst.value(j) - centerInstances.instance(2).value(j), 2));
			}
			
			newInstance.setValue(attrList.get(0), distanceToCluster0);
			newInstance.setValue(attrList.get(1), distanceToCluster1);
			newInstance.setValue(attrList.get(2), distanceToCluster2);
			// LOGGER.debug("" + newInstance);
			ArrayList<String> attrValue = new ArrayList<String>();
			attrValue.add(Double.toString(distanceToCluster0));
			attrValue.add(Double.toString(distanceToCluster1));
			attrValue.add(Double.toString(distanceToCluster2));
			distInstances.add(newInstance);
		}
		
		return distInstances;
	}
	
}
