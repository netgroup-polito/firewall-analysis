/**
 * 
 */
package it.polito.verefoo.test;

import static org.junit.Assert.*;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;



import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.Multiset.Entry;

import it.polito.verefoo.VerefooSerializer;
import it.polito.verefoo.extra.Package1LoggingClass;
import it.polito.verefoo.extra.TestCaseGeneratorAtomicPredicates;
import it.polito.verefoo.extra.TestCaseGeneratorFirewallAnalysis;
import it.polito.verefoo.graph.Predicate;
import it.polito.verefoo.jaxb.NFV;
import it.polito.verefoo.utils.TestResults;

/* Run some instances of TestCaseGeneratorAtomicPredicates. TestCaseGeneratorAtomicPredicates generates XML files for NFV, then this
 * class takes in input those files, for each of them runs Verefoo and print results and other statistics (time to complete, memory usage etc).
 * */
public class TestPerformanceScalabilityFirewallAnalysis {
	
	public static void main(String[] args)  {
		
		runs = 10;
		
		/* FIREWALL ANALYSIS */
		percReqWithPorts = 0.2; //from 0.0 to 1.0
		percReqWithProtoType = 0.5; //from 0.0 to 1.0
		nfirewalls = 1;
		nrules = 926;
		nanomalies = 300;	//Each anomaly inserts 2 rules
		
		seed  = 66361;

		testScalabilityPerformance();

		System.out.println("TEST TERMINATI");
	}
	
	/* Variables to set if you want to automatically create the NFV */
	private static int runs;
	static String prefix = new String("Isol");
	String IPClient[] = new String[runs];
	String IPAllocationPlace[] = new String[runs];
	String IPServer[] = new String[runs];
	static int seed;
	static Random rand;

	static NFV root;
	static String pathfile;
	private static ch.qos.logback.classic.Logger logger;
	
	/* FIREWALL ANALYSIS */
	private static int nfirewalls;
	private static int nrules;
	private static int nanomalies;
	private static double percReqWithPorts;
	private static double percReqWithProtoType;
	
	
	/**
	 * @throws java.lang.Exception
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	private static NFV testCoarse(NFV root) throws Exception{
		long beginAll=System.currentTimeMillis();
		VerefooSerializer test = new VerefooSerializer(root);
		long endAll=System.currentTimeMillis();
		HashMap<String, TestResults> results = test.getTestResults();
		
		long totalTime = endAll - beginAll;
		
		for(String fwname: results.keySet()) {
			TestResults fresult = results.get(fwname);
			String resString = new String("Total time " +  fresult.getTotalTime() + "\tTime AP " + fresult.getAtomicPredCompTime() + "\tTime rewrite rule " +
					fresult.getRewriteRuleCompTime() + "\tTime solve anomalies " + fresult.getSolveAnomaliesCompTime() + "\tTime AND to OR " 
					+ fresult.getAndToORCompTime() + "\tNumber AP " + fresult.getNumberAP());
			
			System.out.println(resString);
			logger.info(resString);
			
			//DEBUG: print atomic predicates
//			for(Map.Entry<Integer, Predicate> entry: fresult.getAtomicPredicates().entrySet()) {
//				System.out.print(entry.getKey()); entry.getValue().print();
//				System.out.println();
//			}
			//END DEBUG
		}
		
        return test.getResult();
	}
	
	
	@Test
	public static void testScalabilityPerformance(){
		    rand= new Random(seed);
		    pathfile = "FIREWALL-ANALYSIS.log";
		    
	        logger =  Package1LoggingClass.createLoggerFor(pathfile, "logSimo/"+pathfile);
	        logger.info("\n\nNRules "+nrules+"\tNAnomalies "+nanomalies+"\tPRP "+percReqWithPorts+"\tPRPT "+percReqWithProtoType);

	        int[] seeds = new int[runs];
	        for(int m=0;m<runs;m++) { 
	        	seeds[m]=Math.abs(rand.nextInt()); 
	        }

	        /* Switch between automatic and manul configuration of the IP*/
	        int k=0, i=0;
	        try {
	        	List<TestCaseGeneratorFirewallAnalysis> nfv = new ArrayList<>();
	        	nfv.add(new TestCaseGeneratorFirewallAnalysis("Test case generator firewall analysis", nfirewalls, nrules, nanomalies, percReqWithPorts, percReqWithProtoType, 1));

	        	for(TestCaseGeneratorFirewallAnalysis f : nfv){

	        		// create a JAXBContext capable of handling the generated classes
	        		//long beginAll=System.currentTimeMillis();
	        		JAXBContext jc = JAXBContext.newInstance( "it.polito.verefoo.jaxb" );
	        		// create an Unmarshaller
	        		Unmarshaller u = jc.createUnmarshaller();
	        		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI); 
	        		Schema schema = sf.newSchema( new File( "./xsd/nfvSchema.xsd" )); 
	        		u.setSchema(schema);
	        		//unmarshal a document into a tree of Java content objects
	        		Marshaller m = jc.createMarshaller();
	        		m.setProperty( Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE );
	        		m.setProperty( Marshaller.JAXB_NO_NAMESPACE_SCHEMA_LOCATION,"./xsd/nfvSchema.xsd");
	        		//for debug purpose  
	        		//m.marshal(f.getNfv(), System.out ); 

	        		do{
	        			for(k = 0; k < runs; k++) {
	        				try {
	        					if(seeds[k] == 1820037872) continue;
	        					m = jc.createMarshaller();
	        					m.setProperty( Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE );
	        					m.setProperty( Marshaller.JAXB_NO_NAMESPACE_SCHEMA_LOCATION,"./xsd/nfvSchema.xsd");

	        					root = f.changeIP(nfirewalls, nrules, nanomalies, percReqWithPorts, percReqWithProtoType, seeds[k]);

	        					//for debug purpose 
	        					//m.marshal( root, System.out );  
	        					i++;
	        					NFV resultNFV = testCoarse(root);
	        					// StringWriter stringWriter = new StringWriter();
	        					//m.marshal( resultNFV, System.out );
	        					//loggerModel.debug(stringWriter.toString());
	        				} catch (Exception e) {
	        					e.printStackTrace();
	        				}

	        			}
	        		}while(i<1);

	        	}
	        } catch (Exception e) {
	        	e.printStackTrace();
	        	fail(e.toString());
	        }
	}
}
