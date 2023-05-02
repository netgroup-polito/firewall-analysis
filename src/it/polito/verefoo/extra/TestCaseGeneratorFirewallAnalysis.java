package it.polito.verefoo.extra;


import java.io.File;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import it.polito.verefoo.jaxb.*;
import it.polito.verefoo.utils.Tuple;

// Auxiliary class to generate  test cases for performance tests (used by TestPerformanceScalabilityAtomicPredicates)
public class TestCaseGeneratorFirewallAnalysis {
	NFV nfv;
	String name;
	
	/*Additional variables */
	int countC = 1;
	int countAP = 1;
	int countS = 1;
	int countP = 1;
	Random rand = null;
	
	String IPC;
	String IPAP;
	String IPS;
	NFV originalNFV;
	
	Set<String> allIPs;
	List<Node> allClients;
	List<Node> allServers;
	List<Node> allAPs;
	List<Node> allNATs;
	List<Node> allFirewalls;
	List<Tuple<String, Node>> lastAPs;
		
	public TestCaseGeneratorFirewallAnalysis(String name, int nfirewalls, int nrules, int nanomalies, 
			double percReqWithPorts, int seed) {
		this.name = name;
		this.rand = new Random(seed); 

		allClients = new ArrayList<Node>();
		allServers = new ArrayList<Node>();
		allAPs = new ArrayList<Node>();
		allNATs = new ArrayList<Node>();
		allFirewalls = new ArrayList<Node>();
		lastAPs = new ArrayList<Tuple<String, Node>>();

		allIPs = new HashSet<String>();
		nfv = generateNFV(nfirewalls, nrules, nanomalies, percReqWithPorts, rand);
	}
	
	
	public NFV changeIP(int nfirewalls, int nrules, int nanomalies, double percReqWithPorts, int seed) {
		this.rand = new Random(seed);
		allClients = new ArrayList<Node>();
		allServers = new ArrayList<Node>();
		allAPs = new ArrayList<Node>();
		allNATs = new ArrayList<Node>();
		allFirewalls = new ArrayList<Node>();
		lastAPs = new ArrayList<Tuple<String, Node>>();

		allIPs = new HashSet<String>();
		return generateNFV(nfirewalls, nrules, nanomalies, percReqWithPorts, rand);
	}
	
	
	//IP that does not contain wildcards
	private String createIP() {
		String ip;
		int first, second, third, forth;
		first = rand.nextInt(256);
		if(first == 0) first++;
		second = rand.nextInt(256);
		third = rand.nextInt(256);
		forth = rand.nextInt(256);
		ip = new String(first + "." + second + "." + third + "." + forth);
		return ip;
	}
	
	private String createRandomIP() {
		boolean notCreated = true;
		String ip = null;
		while(notCreated) {
			ip = createIP();
			if(!allIPs.contains(ip)) {
				notCreated = false;
				allIPs.add(ip);
			}
		}
		
		return ip;
	}
	
	String createIPSupersetOf(String ip1) {
		String ip2;
		
		if(rand.nextBoolean()) {
			ip2 = new String("*");
		} else {
			String[] ip1v = ip1.split(".");
			ip2 = new String(ip1v[0] + "." + ip1v[1] + "." + ip1v[2] + ".-1");
		}
		
		return ip2;
	}
	
	
	public NFV generateNFV(int nfirewalls, int nrules, int nanomalies, double percReqWithPorts, Random rand) {
		
		/* Creation of the test */
		
		NFV nfv = new NFV();
		Graphs graphs = new Graphs();
		PropertyDefinition pd = new PropertyDefinition();
		Constraints cnst = new Constraints();
		NodeConstraints nc = new NodeConstraints();
		LinkConstraints lc = new LinkConstraints();
		cnst.setNodeConstraints(nc);
		cnst.setLinkConstraints(lc);
		nfv.setGraphs(graphs);
		nfv.setPropertyDefinition(pd);
		nfv.setConstraints(cnst);
		Graph graph = new Graph();
		graph.setId((long) 0);
		
		//SERVERS: creation of 1 server
		String IPServer = createRandomIP();
		Node server = new Node();
		server.setFunctionalType(FunctionalTypes.WEBSERVER);
		server.setName(IPServer);
		Configuration confS = new Configuration();
		confS.setName("confB");
		Webserver ws = new Webserver();
		ws.setName(server.getName());
		confS.setWebserver(ws);
		server.setConfiguration(confS);
		allServers.add(server);
	
		String firstIPServer = allServers.get(0).getName();
		
		//CLIENTS: creation of 1 client
		String IPClient = createRandomIP();
		Node client = new Node();
		client.setFunctionalType(FunctionalTypes.WEBCLIENT);
		client.setName(IPClient);
		Configuration confC = new Configuration();
		confC.setName("confA");
		Webclient wc = new Webclient();
		wc.setNameWebServer(firstIPServer);
		confC.setWebclient(wc);
		client.setConfiguration(confC);
		allClients.add(client);
		
		//FIREWALLS: creation of nfirewalls firewalls
		for(int i = 0; i < nfirewalls; i++) {
			String ip = createRandomIP();
			Node firewall = new Node();
			firewall.setFunctionalType(FunctionalTypes.FIREWALL);
			firewall.setName(ip);
			Configuration confF = new Configuration();
			confF.setName("confF");
			Firewall fw = new Firewall();
			confF.setFirewall(fw);
			firewall.setConfiguration(confF);
			allFirewalls.add(firewall);
		}
				
		
		//CHAIN OF FIREWALLS
		//First firewall attached to the client
		Node firstFirewall = allFirewalls.get(0);
		Node firstClient = allClients.get(0);
		Neighbour neighForFirewall = new Neighbour();
		Neighbour neighForClient = new Neighbour();
		neighForFirewall.setName(firstClient.getName());
		neighForClient.setName(firstFirewall.getName());
		firstFirewall.getNeighbour().add(neighForFirewall);
		firstClient.getNeighbour().add(neighForClient);
		
		
		for(int i = 1; i < nfirewalls; i++) {
			Node currentFirewall = allFirewalls.get(i);
			Node previousFirewall = allFirewalls.get(i-1);
			
			Neighbour neighForCurrentFirewall = new Neighbour();
			Neighbour neighForPreviousClient = new Neighbour();
			neighForCurrentFirewall.setName(previousFirewall.getName());
			neighForPreviousClient.setName(currentFirewall.getName());
			currentFirewall.getNeighbour().add(neighForCurrentFirewall);
			previousFirewall.getNeighbour().add(neighForPreviousClient);
		}
		
		//Last firewall attached to the server
		Node lastFirewall = allFirewalls.get(nfirewalls-1);
		Node lastServer = allServers.get(0);
		Neighbour neighForLastFirewall = new Neighbour();
		Neighbour neighForServer = new Neighbour();
		neighForLastFirewall.setName(lastServer.getName());
		neighForServer.setName(lastFirewall.getName());
		lastFirewall.getNeighbour().add(neighForLastFirewall);
		lastServer.getNeighbour().add(neighForServer);
		
		
		//POLICIES: creation of one policy from the client to the server
		String srcNode = allClients.get(0).getName();
		String dstNode = allServers.get(0).getName();
		String srcPort = "*", dstPort = "*";
		
		createPolicy(PName.REACHABILITY_PROPERTY, nfv, graph, srcNode, dstNode, srcPort, dstPort);
		
		
		//FIREWALL RULES
		int ncorrelations = nanomalies/4;
		int nshadowing = nanomalies/4;
		int nredundancy = nanomalies/4;
		int irrilevance = nanomalies - ncorrelations - nshadowing - nredundancy;
		
		for(Node firewall: allFirewalls) {
			
			//Default action
			if(rand.nextBoolean())
				firewall.getConfiguration().getFirewall().setDefaultAction(ActionTypes.ALLOW);
			else 
				firewall.getConfiguration().getFirewall().setDefaultAction(ActionTypes.DENY);
			
			//CORRELATION ANOMALIES => Rx Rc Ry, Rx[action] != Ry[action]
			//Rx Rc Ry: some fields in Rx are subset or equal to the corresponding fields in Ry, the others in Rx are superset of the corresponding in Ry
			for(int i=0; i<ncorrelations; i++) {
				Elements Rx = new Elements();
				Elements Ry = new Elements();
				
				if(rand.nextBoolean()) {
					Rx.setAction(ActionTypes.DENY);
					Ry.setAction(ActionTypes.ALLOW);
				} else {
					Rx.setAction(ActionTypes.ALLOW);
					Ry.setAction(ActionTypes.DENY);
				}
				
				//IP source: IPsrc1 is a subset of IPsrc2
				String IPsrc1 = createIP();
				String IPsrc2;
				if(rand.nextBoolean()) {
					//IPsrc2 superset of IPsrc1
					IPsrc2 = createIPSupersetOf(IPsrc1);
				} else {
					//IPsrc2 = IPsrc1
					IPsrc2 = new String(IPsrc1);
				}
				
				
				
			}
			
			
		}
		
		
		int nRules;
		for(Node firewall: allFirewalls) {
			//introducing some firewalls with zero rules, only with default action
			if(rand.nextBoolean())
				nRules =  maxFWRules; //rand.nextInt(maxFWRules);
			else nRules = 0;
			
			//default action set to oallow
			firewall.getConfiguration().getFirewall().setDefaultAction(ActionTypes.ALLOW);

			for(int i=0; i<nRules; i++) {
				String srcNode = ""; String dstNode = "";
				
				switch(rand.nextInt(2)) {
				case 0: 
					srcNode = allClients.get(rand.nextInt(allClients.size())).getName(); break;
				case 1: 
					srcNode = allServers.get(rand.nextInt(allServers.size())).getName(); break;	
				}
				switch(rand.nextInt(2)) {
				case 0: 
					dstNode = allClients.get(rand.nextInt(allClients.size())).getName(); break;
				case 1: 
					dstNode = allServers.get(rand.nextInt(allServers.size())).getName(); break;	
				}
					
				//check that no reachability requirements match this DENY rule
				boolean reqExists = false;
				for(Property prop: nfv.getPropertyDefinition().getProperty()) {
					if(prop.getSrc().equals(srcNode) && prop.getDst().equals(dstNode) && prop.getName().equals(PName.REACHABILITY_PROPERTY)) {
						reqExists = true;
						break;
					}
				}
				
				if(!reqExists) {
					Elements rule = new Elements();
					rule.setAction(ActionTypes.DENY);
					rule.setSource(srcNode);
					rule.setDestination(dstNode);
					rule.setSrcPort("*");
					rule.setDstPort("*");
					rule.setProtocol(L4ProtocolTypes.ANY);
					firewall.getConfiguration().getFirewall().getElements().add(rule);
				} else i--;
			}
		}
		
		//Create loop in the network: take couples of NAT and link them
		//START CREATE LOOP
//		boolean found;
//		for(int i=0; i<2; i++) {
//			found = false;
//			Node node1 = allNATs.get(rand.nextInt(allNATs.size()));
//			Node node2 = allNATs.get(rand.nextInt(allNATs.size()));
//			
//			if(!node1.getName().equals(node2.getName())) {
//				//Check if the two node are already neighbours
//				for(Neighbour tmpNeig: node1.getNeighbour()) {
//					if(tmpNeig.getName().equals(node2.getName())) {
//						found = true;
//						break;
//					}
//				}
//				if(!found) {
//					Neighbour neig1 = new Neighbour();
//					Neighbour neig2  = new Neighbour();
//					neig1.setName(node2.getName());
//					neig2.setName(node1.getName());
//					node1.getNeighbour().add(neig1);
//					node2.getNeighbour().add(neig2);
//				} else i--;
//					
//			}else i--; //repeat iteration
//		}
		//END CREATE LOOP

		//add the nodes in the graph
		graph.getNode().addAll(allClients);
		graph.getNode().addAll(allServers);
		graph.getNode().addAll(allAPs);
		graph.getNode().addAll(allNATs);
		graph.getNode().addAll(allFirewalls);
		graph.getNode().add(central);
		nfv.getGraphs().getGraph().add(graph);
			
		
		return nfv;
	}

	private void createPolicy(PName type, NFV nfv, Graph graph, String IPClient, String IPServer, String srcPort, String dstPort) {

		Property property = new Property();
		property.setName(type);
		property.setGraph((long) 0);
		property.setSrc(IPClient);
		property.setDst(IPServer);
		property.setSrcPort(srcPort);
		property.setDstPort(dstPort);
		nfv.getPropertyDefinition().getProperty().add(property);
	}
	
	
	public NFV getNfv() {
		return nfv;
	}

	public void setNfv(NFV nfv) {
		this.nfv = nfv;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getIPC() {
		return IPC;
	}

	public void setIPC(String iPC) {
		IPC = iPC;
	}

	public String getIPAP() {
		return IPAP;
	}

	public void setIPAP(String iPAP) {
		IPAP = iPAP;
	}

	public String getIPS() {
		return IPS;
	}

	public void setIPS(String iPS) {
		IPS = iPS;
	}

}
