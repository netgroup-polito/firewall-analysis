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
import java.util.regex.Pattern;

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
			double percReqWithPorts, double percReqWithProtoType, int seed) {
		this.name = name;
		this.rand = new Random(seed); 

		allClients = new ArrayList<Node>();
		allServers = new ArrayList<Node>();
		allAPs = new ArrayList<Node>();
		allNATs = new ArrayList<Node>();
		allFirewalls = new ArrayList<Node>();
		lastAPs = new ArrayList<Tuple<String, Node>>();

		allIPs = new HashSet<String>();
		//nfv = generateNFV(nfirewalls, nrules, nanomalies, percReqWithPorts, percReqWithProtoType, rand);
	}
	
	
	public NFV changeIP(int nfirewalls, int nrules, int nanomalies, double percReqWithPorts, double percReqWithProtoType, int seed) {
		this.rand = new Random(seed);
		allClients = new ArrayList<Node>();
		allServers = new ArrayList<Node>();
		allAPs = new ArrayList<Node>();
		allNATs = new ArrayList<Node>();
		allFirewalls = new ArrayList<Node>();
		lastAPs = new ArrayList<Tuple<String, Node>>();

		allIPs = new HashSet<String>();
		return generateNFV(nfirewalls, nrules, nanomalies, percReqWithPorts, percReqWithProtoType, rand);
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

	// IP that does not contain wildcards
	private String createIPSource() {
		String ip;
		int first, second, third, forth;
		first = 140;
		second = 192;
		third = rand.nextInt(10) + 30;
		forth = rand.nextInt(256);
		ip = new String(first + "." + second + "." + third + "." + forth);
		return ip;
	}
	
	// IP that does not contain wildcards
	private String createIPDestination() {
		String ip;
		int first, second, third, forth;
		first = 161;
		second = 120;
		third = rand.nextInt(10) + 30;
		forth = rand.nextInt(256);
		ip = new String(first + "." + second + "." + third + "." + forth);
		return ip;
	}
	
	private String createPort() {
		int n = rand.nextInt(5)+1;
		return String.valueOf(n);
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
		
		if(rand.nextInt(5) < 1) {
			ip2 = new String("*");
		} else {
			String[] ip1v = ip1.split(Pattern.quote("."));
			ip2 = new String(ip1v[0] + "." + ip1v[1] + "." + ip1v[2] + ".-1");
		}
		
		return ip2;
	}
	
	
	public NFV generateNFV(int nfirewalls, int nrules, int nanomalies, double percReqWithPorts, double percReqWithProtoType, Random rand) {
		
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
		int ngeneralization = nanomalies - ncorrelations - nshadowing - nredundancy;
		
		for(Node firewall: allFirewalls) {
			
			//Default action
			if(rand.nextBoolean())
				firewall.getConfiguration().getFirewall().setDefaultAction(ActionTypes.ALLOW);
			else 
				firewall.getConfiguration().getFirewall().setDefaultAction(ActionTypes.DENY);
			
			//GENERATE CORRELATION ANOMALIES
			for(int i=0; i<ncorrelations; i++) {
				createCorrelationAnomaly(firewall);
			}
			
			//GENERATE SHADOWING ANOMALIES
			for(int i=0; i<nshadowing; i++) {
				createShadowingAnomaly(firewall);
			}
			
			//GENERATE GENERALIZATION ANOMALIES
			for(int i=0; i<ngeneralization; i++) {
				createGeneralizationAnomaly(firewall);
			}
			
			//GENERATE REDUNDANCY ANOMALIES
			for(int i=0; i<nredundancy; i++) {
				createRedundancyAnomaly(firewall);
			}
			
			//GENERATE REMAINING RULES
			for(int i=0; i<nrules-nanomalies*2; i++) {
				
				Elements R = new Elements();
				
				//Action
				if(rand.nextBoolean())
					R.setAction(ActionTypes.DENY);
				else 
					R.setAction(ActionTypes.ALLOW);
				
				//IP source
				String IPSrc = createIP();
				if(rand.nextInt(5) < 1) {
					String[] ipv = IPSrc.split(Pattern.quote("."));
					IPSrc = new String(ipv[0] + "." + ipv[1] + "." + ipv[2] + ".-1");
				}
				R.setSource(IPSrc);
				
				//IP dest
				String IPDst = createIP();
				if(rand.nextInt(5) < 1) {
					String[] ipv = IPDst.split(Pattern.quote("."));
					IPDst = new String(ipv[0] + "." + ipv[1] + "." + ipv[2] + ".-1");
				}
				R.setDestination(IPDst);
				
				//TODO: modificare anche numero di porta e protocollo
				R.setSrcPort("*");
				R.setDstPort("*");
				R.setProtocol(L4ProtocolTypes.ANY);
				
				firewall.getConfiguration().getFirewall().getElements().add(R);
			}
			
			//ADD PORT NUMBER INFO
			int nrulesWithPorts = (int) (nrules * percReqWithPorts);
			for(int i=0; i<nrulesWithPorts; i++) {
				String port = createPort();
				
				//Extract one rule
				Elements rule = firewall.getConfiguration().getFirewall().getElements()
						.get(rand.nextInt(firewall.getConfiguration().getFirewall().getElements().size()));
				
//				if(rand.nextBoolean()) {
//					//Port source
//					if(rule.getSrcPort().equals("*"))
//						rule.setSrcPort(port);
//					else i--;
//				} else {
					//Port destination
					if(rule.getDstPort().equals("*"))
						rule.setDstPort(port);
					else i--;
//				}
			}
			
			
			//ADD PROTOCOL TYPE INFO
			int nrulesWithProtoType = (int) (nrules * percReqWithProtoType);
			for(int i=0; i<nrulesWithProtoType; i++) {
				//Extract one rule
				Elements rule = firewall.getConfiguration().getFirewall().getElements()
						.get(rand.nextInt(firewall.getConfiguration().getFirewall().getElements().size()));
				
				if(!rule.getProtocol().equals(L4ProtocolTypes.ANY)) {
					i--;
					continue;
				}
				
				if(rand.nextBoolean()) {
					rule.setProtocol(L4ProtocolTypes.TCP);
				} else {
					rule.setProtocol(L4ProtocolTypes.UDP);
				}
			}
			
		}

		//add the nodes in the graph
		graph.getNode().addAll(allClients);
		graph.getNode().addAll(allServers);
		graph.getNode().addAll(allAPs);
		graph.getNode().addAll(allNATs);
		graph.getNode().addAll(allFirewalls);
		nfv.getGraphs().getGraph().add(graph);
			
		return nfv;
	}
	
	
	private void createCorrelationAnomaly(Node firewall) {
		//CORRELATION ANOMALIES => Rx Rc Ry, Rx[action] != Ry[action]
		//Rx Rc Ry: some fields in Rx are subset or equal to the corresponding fields in Ry, the others in Rx are superset of the corresponding in Ry
		
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
		String IPsrc1 = createIPSource();
		String IPsrc2;
		if(rand.nextBoolean()) {
			//IPsrc2 superset of IPsrc1
			IPsrc2 = createIPSupersetOf(IPsrc1);
		} else {
			//IPsrc2 = IPsrc1
			IPsrc2 = new String(IPsrc1);
		}
		
		if(rand.nextBoolean()) {
			Rx.setSource(IPsrc1);
			Ry.setSource(IPsrc2);
		} else {
			Rx.setSource(IPsrc2);
			Ry.setSource(IPsrc1);
		}
			
		//IP dest: IPdst1 is a subset of IPdst2
		String IPdst1 = createIPDestination();
		String IPdst2;
		if(rand.nextBoolean()) {
			//IPdst2 superset of IPdst1
			IPdst2 = createIPSupersetOf(IPdst1);
		} else {
			//IPdst2 = IPdst1
			IPdst2 = new String(IPdst1);
		}
		
		if(rand.nextBoolean()) {
			Rx.setDestination(IPdst1);
			Ry.setDestination(IPdst2);
		} else {
			Rx.setDestination(IPdst2);
			Ry.setDestination(IPdst1);
		}
		
		//TODO: modificare anche numero di porta e protocollo
		Rx.setSrcPort("*");
		Rx.setDstPort("*");
		Rx.setProtocol(L4ProtocolTypes.ANY);
		
		Ry.setSrcPort("*");
		Ry.setDstPort("*");
		Ry.setProtocol(L4ProtocolTypes.ANY);
		
		firewall.getConfiguration().getFirewall().getElements().add(Rx);
		firewall.getConfiguration().getFirewall().getElements().add(Ry);
	}
	
	private void createShadowingAnomaly(Node firewall) {
		//SHADOWING ANOMALIES => Ry shadowed by Rx if Rx[order]<Ry[order], Rx[action] != Ry[action], Rx Rem Ry or Ry Rim Rx
		//Rx Rem Ry = exactly matching: each field of Rx is equal to the corresponding in Ry
		//Ry Rim Rx = inclusively matching: if not Rem and each field of Ry is a subset or equal to the corresponding in Rx
		
		Elements Rx = new Elements();
		Elements Ry = new Elements();
		
		if(rand.nextBoolean()) {
			Rx.setAction(ActionTypes.DENY);
			Ry.setAction(ActionTypes.ALLOW);
		} else {
			Rx.setAction(ActionTypes.ALLOW);
			Ry.setAction(ActionTypes.DENY);
		}
		
		//IP source
		String IPsrcy = createIPSource();
		String IPsrcx;
		
		if(rand.nextBoolean()) {
			//Superset
			IPsrcx = createIPSupersetOf(IPsrcy);
		} else {
			//Equal
			IPsrcx = new String(IPsrcy);
		}
		
		Rx.setSource(IPsrcx);
		Ry.setSource(IPsrcy);
		
		//IP dst
		String IPdsty = createIPDestination();
		String IPdstx;
		
		if(rand.nextBoolean()) {
			//Superset
			IPdstx = createIPSupersetOf(IPdsty);
		} else {
			//Equal
			IPdstx = new String(IPdsty);
		}
		
		Rx.setDestination(IPdstx);
		Ry.setDestination(IPdsty);
		
		//TODO: modificare anche numero di porta e protocollo
		Rx.setSrcPort("*");
		Rx.setDstPort("*");
		Rx.setProtocol(L4ProtocolTypes.ANY);
				
		Ry.setSrcPort("*");
		Ry.setDstPort("*");
		Ry.setProtocol(L4ProtocolTypes.ANY);
				
		firewall.getConfiguration().getFirewall().getElements().add(Rx);
		firewall.getConfiguration().getFirewall().getElements().add(Ry);
	}
	
	private void createGeneralizationAnomaly(Node firewall) {
		//GENERALIZATION ANOMALIES => Ry is a generalization of Rx if Rx[order]<Ry[order], Rx[action] != Ry[action], Rx Rim Ry
		//Rx Rim Ry = inclusively matching: if not Rem and each field of Rx is a subset or equal to the corresponding in Ry
		int different = rand.nextInt(5);
		
		Elements Rx = new Elements();
		Elements Ry = new Elements();
		
		if(rand.nextBoolean()) {
			Rx.setAction(ActionTypes.DENY);
			Ry.setAction(ActionTypes.ALLOW);
		} else {
			Rx.setAction(ActionTypes.ALLOW);
			Ry.setAction(ActionTypes.DENY);
		}
		
		//IP source
		String IPsrcx = createIPSource();
		String IPsrcy;
		
		if(rand.nextBoolean() || different == 0) {
			IPsrcy = createIPSupersetOf(IPsrcx);
		} else {
			IPsrcy = new String(IPsrcx);
		}
		
		Rx.setSource(IPsrcx);
		Ry.setSource(IPsrcy);
		
		//IP dst
		String IPdstx = createIPDestination();
		String IPdsty;
		
		if(rand.nextBoolean() || different == 1) {
			IPdsty = createIPSupersetOf(IPdstx);
		} else {
			IPdsty = new String(IPdstx);
		}
		
		Rx.setDestination(IPdstx);
		Ry.setDestination(IPdsty);
		
		//TODO: modificare anche numero di porta e protocollo
		Rx.setSrcPort("*");
		Rx.setDstPort("*");
		Rx.setProtocol(L4ProtocolTypes.ANY);
						
		Ry.setSrcPort("*");
		Ry.setDstPort("*");
		Ry.setProtocol(L4ProtocolTypes.ANY);
						
		firewall.getConfiguration().getFirewall().getElements().add(Rx);
		firewall.getConfiguration().getFirewall().getElements().add(Ry);
		
	}
	
	private void createRedundancyAnomaly(Node firewall) {
		//REDUNDANCY ANOMALIES => Ry is redundant to Rx if Rx[order]<Ry[order], Rx[action] == Ry[action], Rx Rem Ry or Ry Rim Rx
		//Rx Rem Ry = exactly matching: each field of Rx is equal to the corresponding in Ry
		//Ry Rim Rx = inclusively matching: if not Rem and each field of Ry is a subset or equal to the corresponding in Rx
		//Same as Shadowing but with equal actions
		
		Elements Rx = new Elements();
		Elements Ry = new Elements();
		
		if(rand.nextBoolean()) {
			Rx.setAction(ActionTypes.DENY);
			Ry.setAction(ActionTypes.DENY);
		} else {
			Rx.setAction(ActionTypes.ALLOW);
			Ry.setAction(ActionTypes.ALLOW);
		}
		
		//IP source
		String IPsrcy = createIPSource();
		String IPsrcx;
		
		if(rand.nextBoolean()) {
			//Superset
			IPsrcx = createIPSupersetOf(IPsrcy);
		} else {
			//Equal
			IPsrcx = new String(IPsrcy);
		}
		
		Rx.setSource(IPsrcx);
		Ry.setSource(IPsrcy);
		
		//IP dst
		String IPdsty = createIPDestination();
		String IPdstx;
		
		if(rand.nextBoolean()) {
			//Superset
			IPdstx = createIPSupersetOf(IPdsty);
		} else {
			//Equal
			IPdstx = new String(IPdsty);
		}
		
		Rx.setDestination(IPdstx);
		Ry.setDestination(IPdsty);
		
		//TODO: modificare anche numero di porta e protocollo
		Rx.setSrcPort("*");
		Rx.setDstPort("*");
		Rx.setProtocol(L4ProtocolTypes.ANY);
				
		Ry.setSrcPort("*");
		Ry.setDstPort("*");
		Ry.setProtocol(L4ProtocolTypes.ANY);
				
		firewall.getConfiguration().getFirewall().getElements().add(Rx);
		firewall.getConfiguration().getFirewall().getElements().add(Ry);
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
