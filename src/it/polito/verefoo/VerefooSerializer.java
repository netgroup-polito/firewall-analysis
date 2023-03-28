package it.polito.verefoo;

import java.util.List;
import java.util.stream.Collectors;


import com.microsoft.z3.Status;

import it.polito.verefoo.allocation.AllocationGraphGenerator;
import it.polito.verefoo.extra.BadGraphError;
import it.polito.verefoo.jaxb.EType;
import it.polito.verefoo.jaxb.Graph;
import it.polito.verefoo.jaxb.NFV;
import it.polito.verefoo.jaxb.Path;
import it.polito.verefoo.jaxb.Property;
import it.polito.verefoo.utils.TestResults;
import it.polito.verefoo.utils.VerificationResult;

/**
 * This class separates the Verefoo classes implementation from the actual input
 */
public class VerefooSerializer {
	private NFV nfv, result;
	private boolean sat = false;
	private String z3Model;
	private TestResults testResults;
	
	int time = 0;
	
	public int getTime() {
		return time;
	}


	public void setTime(int time) {
		this.time = time;
	}


	/**
	 * Wraps all the Verefoo tasks, executing the z3 procedure for each graph in the
	 * NFV element
	 * 
	 * @param root the NFV element received as input
	 */
	public VerefooSerializer(NFV root) {
		this.nfv = root;
		AllocationGraphGenerator agg = new AllocationGraphGenerator(root);
		root = agg.getAllocationGraph();
		VerefooNormalizer norm = new VerefooNormalizer(root);
		root = norm.getRoot();

		try {
			List<Path> paths = null;
			if (root.getNetworkForwardingPaths() != null)
				paths = root.getNetworkForwardingPaths().getPath();
			for (Graph g : root.getGraphs().getGraph()) {
				List<Property> prop = root.getPropertyDefinition().getProperty().stream()
						.filter(p -> p.getGraph() == g.getId()).collect(Collectors.toList());
				if (prop.size() == 0)
					throw new BadGraphError("No property defined for the Graph " + g.getId(),
							EType.INVALID_PROPERTY_DEFINITION);
				VerefooProxy test = new VerefooProxy(g, root.getHosts(), root.getConnections(), root.getConstraints(),
						prop, paths);
				testResults = test.getTestTimeResults();

			} 
		} catch (BadGraphError e) {
			throw e;
		}
	}


	public String getZ3Model() {
		return z3Model;
	}


	public void setZ3Model(String z3Model) {
		this.z3Model = z3Model;
	}


	/**
	 * @return the original NFV object given in the constructor
	 */
	public NFV getNfv() {
		return nfv;
	}

	/**
	 * @return the NFV object after the computation
	 */
	public NFV getResult() {
		return result;
	}

	/**
	 * @return if the z3 model is sat
	 */
	public boolean isSat() {
		return sat;
	}
	
	public TestResults getTestTimeResults() {
		return testResults;
	}

}
