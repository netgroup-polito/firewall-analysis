package it.polito.verefoo;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import it.polito.verefoo.allocation.AllocationNode;
import it.polito.verefoo.extra.BadGraphError;
import it.polito.verefoo.functions.StatefulPacketFilter;
import it.polito.verefoo.graph.IPAddress;
import it.polito.verefoo.graph.IPAddressRange;
import it.polito.verefoo.graph.PortInterval;
import it.polito.verefoo.graph.Predicate;
import it.polito.verefoo.graph.PredicateRange;
import it.polito.verefoo.graph.ResolutionStrategy;
import it.polito.verefoo.graph.SecurityRequirement;
import it.polito.verefoo.graph.AtomicFlow;
import it.polito.verefoo.graph.AtomicRule;
import it.polito.verefoo.graph.FW;
import it.polito.verefoo.graph.FlowPath;
import it.polito.verefoo.jaxb.*;
import it.polito.verefoo.jaxb.Path.PathNode;
import it.polito.verefoo.utils.APUtils;
import it.polito.verefoo.utils.FirewallAnalysisTask;
import it.polito.verefoo.utils.GenerateFlowsTask;
import it.polito.verefoo.utils.Range;
import it.polito.verefoo.utils.TestResults;

/**
 * 
 * This is the main class that will interface with the Verefoo classes
 *
 */
public class VerefooProxy {
	private List<Property> properties;
	private List<Path> paths;
	private HashMap<String, AllocationNode> allocationNodes;
	private HashMap<Integer, FlowPath> trafficFlowsMap;
	private HashMap<Integer, SecurityRequirement> securityRequirements;
	private List<Node> nodes;
	private APUtils aputils;
	
	/* Atomic predicates */
	HashMap<String, Node> transformersNode = new HashMap<>();
	private HashMap<String, TestResults> firewallTestResults = new HashMap<>();	//one TestResult for each firewall
	
	private HashMap<String, FW> firewalls = new HashMap<>();
	private ResolutionStrategy strategy = ResolutionStrategy.ALLOW_FIRST;
	
	/**
	 * Public constructor for the Verefoo proxy service
	 * 
	 * @param graph              The graph that will be deployed on the network
	 * @param hosts              The list of hosts in the network
	 * @param conns              The connections between hosts
	 * @param paths              the list of paths that the packet flows needs to
	 *                           follow
	 * @param capacityDefinition The list of the capacity for each node that will be
	 *                           deployed
	 * @throws BadGraphError
	 */
	public VerefooProxy(Graph graph, Hosts hosts, Connections conns, Constraints constraints, List<Property> prop,
			List<Path> paths) throws BadGraphError {
		
		// Initialitation of the variables related to the nodes
		allocationNodes = new HashMap<>();
		nodes = graph.getNode();
		nodes.forEach(n -> allocationNodes.put(n.getName(), new AllocationNode(n)));
		
		// Initialitation of the variables related to the requirements
		properties = prop;
		securityRequirements = new HashMap<>();
		int idRequirement = 0;
		for(Property p : properties) {
			securityRequirements.put(idRequirement, new SecurityRequirement(p, idRequirement));
			idRequirement++;
		}
		
		this.paths = paths;
		trafficFlowsMap = generateFlowPaths();

		
		/* Firewall analysis */
		aputils = new APUtils();
		parallelConflictAnalysis();
		
		
		
		//DEBUG: new algorithm to compute Atomic Predicates
		List<IPAddress> listIPAddress = new ArrayList<>();
		
		IPAddress ip1 = new IPAddress("10","0","0","-1", false);
		IPAddress ip2 = new IPAddress("10","0","5","-1", false);
		IPAddress ip3 = new IPAddress("10","0","0","1", false);
		IPAddress ip4 = new IPAddress("10","0","0","2", false);
		IPAddress ip5 = new IPAddress("10","0","5","4", false);
		IPAddress ip6 = new IPAddress("10","9","5","1", false);
		IPAddress ip7 = new IPAddress("10","-1","-1","-1", false);
		IPAddress ip8 = new IPAddress("10","0","-1","-1", false);
		IPAddress ip9 = new IPAddress("10","8","-1","-1", false);
		
		listIPAddress.add(ip1);
		listIPAddress.add(ip2);
		listIPAddress.add(ip3);
		listIPAddress.add(ip4);
		listIPAddress.add(ip5);
		listIPAddress.add(ip6);
		listIPAddress.add(ip7);
		listIPAddress.add(ip8);
		listIPAddress.add(ip9);
		
		List<List<IPAddress>> atomicIPAddresses = aputils.computeAtomicIPAddresses(listIPAddress);
		
		for(List<IPAddress> atomicIPAddress: atomicIPAddresses) {
			int i = 0;
			for(IPAddress IP: atomicIPAddress) {
				if(atomicIPAddress.size() > 1 && atomicIPAddress.toString().equals("*")) continue;
				if(i!=0) System.out.print("AND");
				if(IP.isNeg()) System.out.print("!");
				System.out.print(IP.toString());
				i++;
			}
			System.out.println();
		}
		System.out.println();
		
		
		List<PortInterval> portIntervalList = new ArrayList<>();
		
		PortInterval pi1 = new PortInterval(50, 100, false);
		PortInterval pi2 = new PortInterval(61, 69, false);
		PortInterval pi3 = new PortInterval(200, 500, false);
		PortInterval pi4 = new PortInterval(5, 5, false);
		PortInterval pi5 = new PortInterval(65, 65, false);
		PortInterval pi6 = new PortInterval(251, 255, false);
		
		portIntervalList.add(pi1);
		portIntervalList.add(pi2);
		portIntervalList.add(pi3);
		portIntervalList.add(pi4);
		portIntervalList.add(pi5);
		portIntervalList.add(pi6);
		
		List<List<PortInterval>> atomicPortIntervals = aputils.computeAtomicPortIntervals(portIntervalList);
		
		for(List<PortInterval> atomicPortInterval: atomicPortIntervals) {
			int i=0;
			for(PortInterval pi: atomicPortInterval) {
				if(atomicPortInterval.size() > 1 && pi.toString().equals("*")) continue;
				if(i!=0) System.out.print("AND");
				if(pi.isNeg()) System.out.print("!");
				System.out.print(pi.toString());
				i++;
			}
			System.out.println();
		}
		
		
		
		
		
		
		
		
		//DEBUG: print firewall Atomic Predicates
//		for(FW fw: firewalls.values()) {
//			System.out.println("FIREWALL " + fw.getName() + " Number of APs " + fw.getFirewallAtomicPredicates().size());
//			for(HashMap.Entry<Integer, Predicate> entry: fw.getFirewallAtomicPredicates().entrySet()) {
//				System.out.print(entry.getKey() + " ");
//				entry.getValue().print();
//				System.out.println();
//			}
//		}
		//END DEBUG
		
		//DEBUG: print firewall original rule and related atomic rules
//		for(FW fw: firewalls.values()) {
//			System.out.println("FIREWALL RULES");
//			for(AtomicRule rule: fw.getAtomicRules()) {
//				rule.print();
//			}
//		}
		//END DEBUG
		
		//DEBUG: print firewall anomalies
//		for(FW fw: firewalls.values()) {
//			System.out.print(strategy + " Allowed: ");
//			for(int ap: fw.getAllowedAPs())
//				System.out.print(ap + " ");
//			System.out.print(", PRED ");
//			for(Predicate ap: fw.getAllowedPredicates())
//				ap.print();
//			System.out.println();
//			System.out.print("\tPRED IN OR: ");
//			for(PredicateRange prange: fw.getAllowedPredicatesRange())
//				prange.print();
//			
//			System.out.print("\n" + strategy + " Denied: ");
//			for(int ap: fw.getDeniedAPs())
//				System.out.print(ap + " ");
//			System.out.print(", PRED ");
//			for(Predicate ap: fw.getDeniedPredicates())
//				ap.print();
//			System.out.println();
//			System.out.print("\tPRED IN OR: ");
//			for(PredicateRange prange: fw.getDeniedPredicatesRange())
//				prange.print();
//			System.out.println();
//			System.out.println();
//		
//		}
		//END DEBUG
		
		
		//DEBUG: test SPLIT
//		System.out.println("NUOVO TEST SPLITTTT");
//		IPAddress ip1 = new IPAddress("10.0.-1.-1", false);
//		IPAddress ip2 = new IPAddress("10.0.3.-1", true);
//		IPAddress ip3 = new IPAddress("10.0.0.4", true);
//		IPAddress ip4 = new IPAddress("10.0.5.4", true);
//		
//		IPAddressRange ipar1 = new IPAddressRange(ip1);
//		IPAddressRange ipar2 = new IPAddressRange(ip2);
//		IPAddressRange ipar3 = new IPAddressRange(ip3);
//		IPAddressRange ipar4 = new IPAddressRange(ip4);
//		
//		SortedSet<IPAddressRange> list = new TreeSet<>();
//		list.add(ipar1); list.add(ipar2); list.add(ipar3); list.add(ipar4);
//		
//		Range p1 = new Range(10, 200);
//		Range p2 = new Range(15, 18);
//		Range p3 = new Range(39, 80);
//		
//		SortedSet<Range> pList = new TreeSet<>();
//		pList.add(p1); pList.add(p2); pList.add(p3);
//		
//		PredicateRange pred = new PredicateRange();
//		pred.setIPSrcList(list);
//		pred.setpSrcList(pList);
		//END DEBUG
		
		
		//DEBUG: test merge IPAddress
//		IPAddressRange newipar1 = new IPAddressRange(new Range(10,10), new Range(0,0), new Range(5,8), new Range(4,4));
//		IPAddressRange newipar2 = new IPAddressRange(new Range(10,10), new Range(0,0), new Range(9,200), new Range(4,4));
//		
//		IPAddressRange res = newipar2.isContiguousTo(newipar1);
//		System.out.println("MERGE " + res);
		
	}
	
//	private void computeAtomicFlows() {
//		ExecutorService threadPool = Executors.newFixedThreadPool(10);
//		List<Future<?>> tasks = new ArrayList<Future<?>>();
//		
//		System.out.println("NUMBER OF REQUIREMENTS: " + securityRequirements.size());
//		System.out.println("Computing atomic flows:");
//		AtomicInteger atomicId = new AtomicInteger();
//		int debugIndex = 0;
//		for(SecurityRequirement sr : securityRequirements.values()) {
//			if(debugIndex == 150) {
//				debugIndex = 0;
//				System.out.println();
//			}
//			debugIndex++;
//			System.out.print("*");
//			APUtils aputilsNew = new APUtils(); 
//			tasks.add(threadPool.submit(new GenerateFlowsTask(sr, networkAtomicPredicates, aputilsNew, transformersNode, atomicId)));
//		}
//		
//		threadPool.shutdown();
//		//Join results
//		for(Future<?> fut: tasks) {
//			try {
//				fut.get();
//			} catch (InterruptedException | ExecutionException e) {
//				e.printStackTrace();
//			}
//		}
//		System.out.println();	
//		
//		//DEBUG: print atomic flows for each requirement
////		for(SecurityRequirement sr : securityRequirements.values()) {
////			Property prop = sr.getOriginalProperty();
////			System.out.println("\nConsidering requirement {"+prop.getSrc()+","+prop.getSrcPort()+","+prop.getDst()+","+prop.getDstPort()+","+prop.getLv4Proto()+"}");   
////			for(FlowPath flow: sr.getFlowsMap().values()) {
////				Map<Integer, AtomicFlow> atomicFlowsMap = flow.getAtomicFlowsMap();
////				Map<Integer, AtomicFlow> atomicFlowsToDiscardMap = flow.getAtomicFlowsToDiscardMap();
////				List<AllocationNode> path = flow.getPath();
////				if(atomicFlowsMap != null) {
////					System.out.println("Atomic flows accepted");
////					for(Map.Entry<Integer, AtomicFlow> entry: atomicFlowsMap.entrySet()) {
////						int index = 0;
////						System.out.print(entry.getKey() + ": ");
////						for(Integer ap: entry.getValue().getAtomicPredicateList()) {
////							System.out.print(path.get(index).getIpAddress() + ", " + ap + ", ");
////							index++;
////						}
////						System.out.println(path.get(index).getIpAddress());
////					}
////					System.out.println("Atomic flows discarded");
////					for(Map.Entry<Integer, AtomicFlow> entry: atomicFlowsToDiscardMap.entrySet()) {
////						int index = 0;
////						System.out.print(entry.getKey() + ": ");
////						for(Integer ap: entry.getValue().getAtomicPredicateList()) {
////							System.out.print(path.get(index).getIpAddress() + ", " + ap + ", ");
////							index++;
////						}
////						System.out.println();
////					}
////				}
////			}
////		}
////		System.out.println();
//		//END DEBUG
//		
//		//Total number of flows
//		long totalFlows = 0;
//		for(SecurityRequirement sr : securityRequirements.values()) {
//			for(FlowPath flowPath: sr.getFlowsMap().values()) {
//				totalFlows += flowPath.getAtomicFlowsMap().size();
//			}
//		}
//		testResults.setTotalFlows(totalFlows);
//		
//		//built map that assign to each allocation node the set of atomic predicates in input
//		for(SecurityRequirement sr : securityRequirements.values()) {
//			for(FlowPath flowPath: sr.getFlowsMap().values()) {
//				List<AllocationNode> path = flowPath.getPath();
//				for(AtomicFlow atomicFlow: flowPath.getAtomicFlowsMap().values()) {
//					//for source node don't add nothing
//					int index = 1;
//					for(Integer ap: atomicFlow.getAtomicPredicateList()) {
//						path.get(index).addAtomicPredicateInInput(flowPath.getIdFlow(), atomicFlow.getFlowId(), ap);
//						if(transformersNode.containsKey(path.get(index).getIpAddress()) 
//								&& transformersNode.get(path.get(index).getIpAddress()).getFunctionalType() == FunctionalTypes.FIREWALL) {
//							//If the node is a firewall, check if the predicate is allowed to pass or if it is dropped
//							if(path.get(index).getForwardBehaviourList().contains(ap) || path.get(index).getDroppedList().contains(ap))
//								{
//								index++;
//								continue; //already checked
//								}
//							boolean foundIntersection = false;
//							for(Predicate allowed: path.get(index).getForwardBehaviourPredicateList()) {
//								Predicate intersectionPredicate = aputils.computeIntersection(networkAtomicPredicates.get(ap), allowed);
//								if(intersectionPredicate != null && aputils.APCompare(intersectionPredicate, networkAtomicPredicates.get(ap))) {
//									foundIntersection = true;	
//									break;
//								} 
//							}
//							
//							if(foundIntersection) {
//								path.get(index).addForwardingPredicate(ap);
//							} else {
//								path.get(index).addDroppedPredicate(ap);
//							}
//						}
//						
//						if(transformersNode.containsKey(path.get(index).getIpAddress()) 
//								&& transformersNode.get(path.get(index).getIpAddress()).getFunctionalType() == FunctionalTypes.STATEFUL_FIREWALL) {
//							StatefulPacketFilter spf = (StatefulPacketFilter) path.get(index).getPlacedNF();
//							if(spf.getAllowAtomicPredicates().values().contains(ap) || spf.getDenyAtomicPredicates().contains(ap) || spf.getAllowCondAtomicPredicates().values().contains(ap) || spf.getAllowCondInvAtomicPredicates().values().contains(ap))
//								continue; //already checked
//							
//							boolean foundIntersection = false;
//							System.out.println("ALLOWEDCOND: " );
//							for(Map.Entry<Integer,Predicate> allowedCond: spf.getAllowCondPredicates().entrySet()) {
//								allowedCond.getValue().print();
//								Predicate intersectionPredicate = aputils.computeIntersection(networkAtomicPredicates.get(ap), allowedCond.getValue());
//								if(intersectionPredicate != null && aputils.APCompare(intersectionPredicate, networkAtomicPredicates.get(ap))) {
//									foundIntersection = true;	
//									spf.addAllowCondAtomicPredicate(allowedCond.getKey(), ap);
//									break;
//								} 
//							}
//							if(!foundIntersection) {
//								System.out.println("ALLOWEDCONDINV: " );
//								for(Map.Entry<Integer,Predicate> allowedCondInv: spf.getAllowCondInvPredicates().entrySet()) {
//									allowedCondInv.getValue().print();
//									Predicate intersectionPredicate = aputils.computeIntersection(networkAtomicPredicates.get(ap), allowedCondInv.getValue());
//									if(intersectionPredicate != null && aputils.APCompare(intersectionPredicate, networkAtomicPredicates.get(ap))) {
//										foundIntersection = true;	
//										spf.addAllowCondInvAtomicPredicate(allowedCondInv.getKey(), ap);
//										break;
//									} 
//								}
//								if(!foundIntersection) {
//									System.out.println("ALLOWED: " );
//									for(Map.Entry<Integer,Predicate> allowed: spf.getAllowPredicates().entrySet()) {
//										allowed.getValue().print();
//										Predicate intersectionPredicate = aputils.computeIntersection(networkAtomicPredicates.get(ap), allowed.getValue());
//										if(intersectionPredicate != null && aputils.APCompare(intersectionPredicate, networkAtomicPredicates.get(ap))) {
//											foundIntersection = true;	
//											spf.addAllowAtomicPredicate(allowed.getKey(), ap);
//											break;
//										} 
//									}
//									if(!foundIntersection) {
//										System.out.println("DENIED: " );
//										System.out.println(ap);
//										spf.addDenyAtomicPredicate(ap);
//									}
//								}
//							}
//							
//						}
//						
//						
//						
//						index++;
//					}
//					
//					
//				}
//			}
//		}
//	}
		

	
//	private void fillTransformationMap() {
//		System.out.println("Filling transformers map");
//		for(Node node: transformersNode.values()) {
//			System.out.print("*");
//			HashMap<Integer, List<Integer>> resultMap = allocationNodes.get(node.getName()).getTransformationMap();
//			if(node.getFunctionalType() == FunctionalTypes.NAT) {
//				HashMap<String, List<Integer>> shadowingMap = new HashMap<>(); //grouped by dest address
//				HashMap<String, List<Integer>> shadowedMap = new HashMap<>(); //grouped by dest address
//				HashMap<String, List<Integer>> reconversionMap = new HashMap<>(); //grouped by source address
//				HashMap<String, List<Integer>> reconvertedMap = new HashMap<>();  //grouped by source address
//				List<Integer> notChaingingPredicateList = new ArrayList<>();
//				List<IPAddress> natIPSrcAddressList = new ArrayList<>();
//				for(String src: node.getConfiguration().getNat().getSource()) 
//					natIPSrcAddressList.add(new IPAddress(src, false));
//				IPAddress natIPAddress = new IPAddress(node.getName(), false);
//				
//				for(HashMap.Entry<Integer, Predicate> apEntry: networkAtomicPredicates.entrySet()) {
//					Predicate ap = apEntry.getValue();
//					//if source ip address list or dest ip address list have size != 1, it means it is a complex predicates so it can not be a shodowing/reconversion predicates
//					if(ap.getIPSrcListSize() != 1 || ap.getIPDstListSize() != 1) continue;
//					if(ap.hasIPDstNotIncludedIn(natIPSrcAddressList) && !ap.hasIPDstEqual(natIPAddress)) {
//						if(ap.hasIPSrcEqual(natIPAddress)) {
//							//2*: if dest is not a src address of the NAT (so it is a public address) and ip source = ip NAT, this is a shadowed predicate
//							//{IP NAT, public address}
//							if(!shadowedMap.containsKey(ap.firstIPDstToString())) {
//								List<Integer> list = new ArrayList<>();
//								list.add(apEntry.getKey());
//								shadowedMap.put(ap.firstIPDstToString(), list);
//							} else {
//								shadowedMap.get(ap.firstIPDstToString()).add(apEntry.getKey());
//							}
//						} 
//						else {
//							//1*: if dest is not a src address of the NAT (so it is a public address), while src is a src address of NAT (private address),
//							//this is a shadowing predicates {private address, public address}
//							if(ap.hasIPSrcEqualOrIncludedIn(natIPSrcAddressList))
//								if(!shadowingMap.containsKey(ap.firstIPDstToString())) {
//									List<Integer> list = new ArrayList<>();
//									list.add(apEntry.getKey());
//									shadowingMap.put(ap.firstIPDstToString(), list);
//								} else {
//									shadowingMap.get(ap.firstIPDstToString()).add(apEntry.getKey());
//								}
//						}
//					} else if(ap.hasIPSrcNotIncludedIn(natIPSrcAddressList) && !ap.hasIPSrcEqual(natIPAddress)) {
//						if(ap.hasIPDstEqual(natIPAddress)) {
//							//3*: src not included in NAT src, dest = IP NAT -> reconversion predicate {public address, IP NAT}
//							if(!reconversionMap.containsKey(ap.firstIPSrcToString())) {
//								List<Integer> list = new ArrayList<>();
//								list.add(apEntry.getKey());
//								reconversionMap.put(ap.firstIPSrcToString(), list);
//							} else {
//								reconversionMap.get(ap.firstIPSrcToString()).add(apEntry.getKey());
//							}
//						} else if(ap.hasIPDstEqualOrIncludedIn(natIPSrcAddressList)) {
//							//4*: src not included in NAT src, dest included in NAT src -> reconverted predicate {public address, private address}
//							if(!reconvertedMap.containsKey(ap.firstIPSrcToString())) {
//								List<Integer> list = new ArrayList<>();
//								list.add(apEntry.getKey());
//								reconvertedMap.put(ap.firstIPSrcToString(), list);
//							} else {
//								reconvertedMap.get(ap.firstIPSrcToString()).add(apEntry.getKey());
//							}
//						}
//					} else if(ap.hasIPSrcEqualOrIncludedIn(natIPSrcAddressList) && ap.hasIPDstEqualOrIncludedIn(natIPSrcAddressList)) {
//						//5*: src included in NAT src (private) and dst included in NAT src (private) -> predicate is just forwarded without transformation
//						notChaingingPredicateList.add(apEntry.getKey());
//					}
//				}
//				//Fill the map: to each shadowing predicate assign the corresponding shadowed predicate, to each reconversion predicate assign the corresponding
//				//list of reconverted predicates. NOTE: take also in consideration the ports and prototype of the predicate
//				for(HashMap.Entry<String, List<Integer>> entry: shadowingMap.entrySet()) {
//					for(Integer shing: entry.getValue()) {
//						List<Integer> result = new ArrayList<>();
//						if(!shadowedMap.containsKey(entry.getKey())) break;
//						for(Integer shed: shadowedMap.get(entry.getKey())) {
//							if(aputils.APComparePrototypeList(
//									networkAtomicPredicates.get(shing).getProtoTypeList(), networkAtomicPredicates.get(shed).getProtoTypeList())
//									&& aputils.APComparePortList(networkAtomicPredicates.get(shing).getpSrcList(), networkAtomicPredicates.get(shed).getpSrcList())
//									&& aputils.APComparePortList(networkAtomicPredicates.get(shing).getpDstList(), networkAtomicPredicates.get(shed).getpDstList())) 
//								result.add(shed);
//						}
//						resultMap.put(shing, result);
//					}
//				}
//				for(HashMap.Entry<String, List<Integer>> entry: reconversionMap.entrySet()) {
//					for(Integer rcvion: entry.getValue()) {
//						List<Integer> result = new ArrayList<>();
//						if(!reconvertedMap.containsKey(entry.getKey())) break;
//						for(Integer rcved: reconvertedMap.get(entry.getKey())) {
//							if(aputils.APComparePrototypeList(
//									networkAtomicPredicates.get(rcvion).getProtoTypeList(), networkAtomicPredicates.get(rcved).getProtoTypeList())
//									&& aputils.APComparePortList(networkAtomicPredicates.get(rcvion).getpSrcList(), networkAtomicPredicates.get(rcved).getpSrcList())
//									&& aputils.APComparePortList(networkAtomicPredicates.get(rcvion).getpDstList(), networkAtomicPredicates.get(rcved).getpDstList()))
//								result.add(rcved);
//						}
//						resultMap.put(rcvion, result);
//					}
//				}
//			}
//		}
//		System.out.println();
//	}
	
	
//	private void rewriteFirewallRules() {
//		
//		for(Node node: transformersNode.values()) {
//			if(node.getFunctionalType() == FunctionalTypes.FIREWALL) {
//				
//				int count = 1;
//				List<AtomicRule> atomicRules = new ArrayList<>();
//	
//				for(Elements rule: node.getConfiguration().getFirewall().getElements()) {
//
//					Predicate rulePred = new Predicate(rule.getSource(), false, rule.getDestination(), false, 
//							rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol());
//					
//					AtomicRule newAtomicRule = new AtomicRule(rule.getAction(), count, rulePred);
//					
//					for(HashMap.Entry<Integer, Predicate> apEntry: networkAtomicPredicates.entrySet()) {
//						Predicate intersectionPredicate = aputils.computeIntersection(apEntry.getValue(), rulePred);
//						if(intersectionPredicate != null && aputils.APCompare(intersectionPredicate, apEntry.getValue())
//								&& !apEntry.getValue().hasIPDstOnlyNegs()) {
//							//System.out.print(apEntry.getKey() + " "); apEntry.getValue().print();
//							newAtomicRule.addAtomicPredicates(apEntry.getKey());
//						}
//					}
//					count++;
//					atomicRules.add(newAtomicRule);
//				}
//				
//				firewalls.put(node.getName(), new FW(node.getName(), atomicRules));
//			}
//		}
//		
//		
//		//DEBUG: print firewall original rule and related atomic rules
//		for(FW fw: firewalls.values()) {
//			System.out.println("FIREWALL " + fw.getName());
//			for(AtomicRule rule: fw.getAtomicRules()) {
//				rule.print();
//			}
//		}
//		//END DEBUG
//	}
	
//	private void solveFirewallAnomalies() {
//		
//		/* Priority first:
//		 * Ordino le regole all'interno del firewall per priorità. Scansiono una regola per volta e un suo ap per volta.
//		 * Se l'ap è già presente in una delle due liste, allowed o denied, non faccio nulla
//		 * Altrimenti lo inserisco nella lista corrsipondente in base all'azione della regola
//		 */
//		for (FW fw : firewalls.values()) {
//
//			List<AtomicRule> atomicRules = fw.getAtomicRules();
//			Collections.sort(atomicRules); // rules sorted by priority
//
//			SortedSet<Integer> allowedAPs = new TreeSet<>();
//			SortedSet<Integer> deniedAPs = new TreeSet<>();
//
//			for (AtomicRule rule : atomicRules) {
//				for (int ap : rule.getAtomicPredicates()) {
//					if (!allowedAPs.contains(ap) && !deniedAPs.contains(ap)) {
//						// First time we find this ap -> insert it into allowed or denied, based on rule
//						// action
//						if (rule.getAction().equals(ActionTypes.DENY))
//							deniedAPs.add(ap);
//						else
//							allowedAPs.add(ap);
//					}
//				}
//			}
//
//			fw.setPFAllowedAPs(allowedAPs);
//			fw.setPFDeniedAPs(deniedAPs);
//		}
//		
//		/* Allow First:
//		 * Scansiono prima tutte le regole ALLOW e inserisco i loro ap all'interno della lista allowed (se non sono già presenti).
//		 * Poi scansiono le regole DENY e aggiungo a denied gli ap che non sono già presenti in allowed
//		*/
//		for (FW fw : firewalls.values()) {
//
//			List<AtomicRule> atomicRules = fw.getAtomicRules();
//
//			SortedSet<Integer> allowedAPs = new TreeSet<>();
//			SortedSet<Integer> deniedAPs = new TreeSet<>();
//
//			for(AtomicRule rule: atomicRules) {
//				if(rule.getAction().equals(ActionTypes.ALLOW)) {
//					for(int ap: rule.getAtomicPredicates()) {
//						if(!allowedAPs.contains(ap))
//							allowedAPs.add(ap);
//					}
//				}
//			}
//
//			for(AtomicRule rule: atomicRules) {
//				if(rule.getAction().equals(ActionTypes.DENY)) {
//					for(int ap: rule.getAtomicPredicates()) {
//						if(!allowedAPs.contains(ap) && !deniedAPs.contains(ap))
//							deniedAPs.add(ap);
//					}
//				}
//			}
//
//			fw.setAFAllowedAPs(allowedAPs);
//			fw.setAFDeniedAPs(deniedAPs);
//		}
//		
//		/* Deny First: stesso ragionamento di Allow first */
//		for (FW fw : firewalls.values()) {
//				
//			List<AtomicRule> atomicRules = fw.getAtomicRules();
//				
//				SortedSet<Integer> allowedAPs = new TreeSet<>();
//				SortedSet<Integer> deniedAPs = new TreeSet<>();
//				
//				for(AtomicRule rule: atomicRules) {
//					if(rule.getAction().equals(ActionTypes.DENY)) {
//						for(int ap: rule.getAtomicPredicates()) {
//							if(!deniedAPs.contains(ap))
//								deniedAPs.add(ap);
//						}
//					}
//				}
//				
//				for(AtomicRule rule: atomicRules) {
//					if(rule.getAction().equals(ActionTypes.ALLOW)) {
//						for(int ap: rule.getAtomicPredicates()) {
//							if(!deniedAPs.contains(ap) && !allowedAPs.contains(ap))
//								allowedAPs.add(ap);
//						}
//					}
//				}
//				
//				fw.setDFAllowedAPs(allowedAPs);
//				fw.setDFDeniedAPs(deniedAPs);		
//		}
//		
//		//DEBUG: print firewall anomalies
//		for(FW fw: firewalls.values()) {
//			System.out.print("PRIORITY FIRST Allowed: ");
//			for(int ap: fw.getPFAllowedAPs())
//				System.out.print(ap + " ");
//			System.out.print("\nPRIORITY FIRST Denied: ");
//			for(int ap: fw.getPFDeniedAPs())
//				System.out.print(ap + " ");
//			System.out.println();
//			
//			System.out.print("ALLOWED FIRST Allowed: ");
//			for(int ap: fw.getAFAllowedAPs())
//				System.out.print(ap + " ");
//			System.out.print("\nALLOWED FIRST Denied: ");
//			for(int ap: fw.getAFDeniedAPs())
//				System.out.print(ap + " ");
//			System.out.println();
//			
//			System.out.print("DENIED FIRST Allowed: ");
//			for(int ap: fw.getDFAllowedAPs())
//				System.out.print(ap + " ");
//			System.out.print("\nDENIED FIRST Denied: ");
//			for(int ap: fw.getDFDeniedAPs())
//				System.out.print(ap + " ");
//			System.out.println();
//		}
//		//END DEBUG
//	}
	
	private void parallelConflictAnalysis() {
		ExecutorService threadPool = Executors.newFixedThreadPool(10);
		List<Future<?>> tasks = new ArrayList<Future<?>>();
		
		for(Node node: transformersNode.values()) {
			if(node.getFunctionalType() == FunctionalTypes.FIREWALL) {
				//For each firewall, compute its related Atomic Predicates and perform Conflict Analysis
				APUtils aputilsNew = new APUtils();
				TestResults fresult = new TestResults();
				tasks.add(threadPool.submit(new FirewallAnalysisTask(node, firewalls, aputilsNew, strategy, fresult)));
				firewallTestResults.put(node.getName(), fresult);
			}
		}
		
		//JOIN
		threadPool.shutdown();
		for(Future<?> fut: tasks) {
			try {
				fut.get();
			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace();
			}
		}	
	}
	
//	private HashMap<Integer, Predicate> generateAtomicPredicatesForFirewallAnalysis(){
//		List<Predicate> predicates = new ArrayList<>();
//		List<Predicate> atomicPredicates = new ArrayList<>();
//		
//		for(Node node: transformersNode.values()) {
//			
//			if(node.getFunctionalType() == FunctionalTypes.FIREWALL) {
//				
//				List<Predicate> allowedList = new ArrayList<>();
//				List<Predicate> deniedList = new ArrayList<>();
//				
//				boolean deniedListChanged = false;
//				for(Elements rule: node.getConfiguration().getFirewall().getElements()) {
//					if(rule.getAction().equals(ActionTypes.DENY)) {
//						//deny <--- deny V rule-i
//						deniedList.add(new Predicate(rule.getSource(), false, rule.getDestination(), false, 
//								rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol()));
//						deniedListChanged = true;
//					} else {
//						//allowed <--- allowed V (rule-i AND !denied)
//						Predicate toAdd = new Predicate(rule.getSource(), false, rule.getDestination(), false, 
//								rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol());
//						List<Predicate> allowedToAdd = aputils.computeAllowedForRule(toAdd, deniedList, deniedListChanged);
//						for(Predicate allow: allowedToAdd) {
//							if(!aputils.isPredicateContainedIn(allow, allowedList))
//								allowedList.add(allow);
//						}
//					}
//				}
//				//Check default action: if DENY do nothing
//				if(node.getConfiguration().getFirewall().getDefaultAction().equals(ActionTypes.ALLOW)) {
//					Predicate toAdd = new Predicate("*", false, "*", false, "*", false, "*", false, L4ProtocolTypes.ANY);
//					List<Predicate> allowedToAdd = aputils.computeAllowedForRule(toAdd, deniedList, deniedListChanged);
//					for(Predicate allow: allowedToAdd) {
//						if(!aputils.isPredicateContainedIn(allow, allowedList))
//							allowedList.add(allow);
//					}
//				}
//				
//				for(Predicate p: allowedList) {
//					if(!predicates.contains(p))
//						predicates.add(p);
//				}	
//			}
//		}
//		
//		//Now we have the list of predicates on which we have to compute the set of atomic predicates, so compute atomic predicates
//		atomicPredicates = aputils.computeAtomicPredicates(atomicPredicates, predicates);
//		
//		//Give to each atomic predicate an identifier
//		int index = 0;
//		for(Predicate p: atomicPredicates) {
//			networkAtomicPredicates.put(index, p);
//			index++;
//		}
//		
//		//DEBUG: print atomic predicates
//		System.out.println("ATOMIC PREDICATES " + networkAtomicPredicates.size());
////		for(HashMap.Entry<Integer, Predicate> entry: networkAtomicPredicates.entrySet()) {
////			System.out.print(entry.getKey() + " ");
////			entry.getValue().print();
////		}
//		//END DEBUG
//		
//		return networkAtomicPredicates;
//	}
	
	
	
	/* Starting from source and destination of each requirement, compute related atomic predicates. Then add to the computed set
	 * also atomic predicates representing input packet classes for each transformer (here we are considering only NAT and firewall)*/
//	private HashMap<Integer, Predicate> generateAtomicPredicateNew(){
//		List<Predicate> predicates = new ArrayList<>();
//		List<Predicate> atomicPredicates = new ArrayList<>();
//		List<String> srcList = new ArrayList<>();
//		List<String> dstList = new ArrayList<>();
//		List<String> srcPList = new ArrayList<>();
//		List<String> dstPList = new ArrayList<>();
//		List<L4ProtocolTypes> dstProtoList = new ArrayList<>();
//
//		//Generate predicates representing source and predicates representing destination of each requirement
//		for(SecurityRequirement sr : securityRequirements.values()) {
//			Property property = sr.getOriginalProperty();
//			String IPSrc = property.getSrc();
//			String IPDst = property.getDst();
//			String pSrc = property.getSrcPort() != null &&  !property.getSrcPort().equals("null") ? property.getSrcPort() : "*";
//			String pDst = property.getDstPort() != null &&  !property.getDstPort().equals("null") ? property.getDstPort() : "*";
//			L4ProtocolTypes proto = property.getLv4Proto() != null ? property.getLv4Proto() : L4ProtocolTypes.ANY;
//			srcList.add("*"); dstList.add("*"); srcPList.add("*"); dstPList.add("*"); dstProtoList.add(L4ProtocolTypes.ANY);
//			
//			//if we have already inserted this source into the list, we can skip it
//			if(!srcList.contains(IPSrc) || !srcPList.contains(pSrc)) {
//				if(!srcList.contains(IPSrc))
//					srcList.add(IPSrc);
//				else IPSrc = "*";
//				if(!srcPList.contains(pSrc)) 
//					srcPList.add(pSrc);
//				else pSrc = "*";
//				
//				Predicate srcPredicate = new Predicate(IPSrc, false, "*", false, pSrc, false, "*", false, L4ProtocolTypes.ANY);
//				predicates.add(srcPredicate);
//			}
//			
//			//if we have already inserted this destination into the list, we can skip it
//			if(!dstList.contains(IPDst) || !dstPList.contains(pDst) || !dstProtoList.contains(proto)) {
//				if(!dstList.contains(IPDst)) dstList.add(IPDst);
//				else IPDst = "*";
//				if(!dstPList.contains(pDst)) dstPList.add(pDst);
//				else pDst = "*";
//				if(!dstProtoList.contains(proto)) dstProtoList.add(proto);
//				else proto = L4ProtocolTypes.ANY;
//				
//				Predicate dstPredicate = new Predicate("*", false, IPDst, false, "*", false, pDst, false, proto);
//				predicates.add(dstPredicate);
//			}
//		}
//
//		//Generate predicates representing input packet class for each transformers
//		for(Node node: transformersNode.values()) {
//			if(node.getFunctionalType() == FunctionalTypes.NAT) {
//				//Compute list of shadowed and reconverted (only those related to requirements sources), considering NAT source addresses list
//				List<String> shadowedAddressesListSrc = new ArrayList<>();
//				List<String> shadowedAddressesListDst = new ArrayList<>();
//				for(String shadowedAddress: node.getConfiguration().getNat().getSource()) {
//					for(String ips: srcList) {
//						if(shadowedAddress.equals(ips) || aputils.isIncludedIPString(shadowedAddress, ips)) {
//							shadowedAddressesListSrc.add(shadowedAddress);
//							break;
//						}
//					}
//					for(String ipd: dstList) {
//						if(shadowedAddress.equals(ipd) || aputils.isIncludedIPString(shadowedAddress, ipd)) {
//							shadowedAddressesListDst.add(shadowedAddress);
//							break;
//						}
//					}
//				}
//				//Generate and add shadowing predicates
//				for(String shadowed: shadowedAddressesListSrc) {
//					if(!srcList.contains(shadowed)) {
//						Predicate shpred = new Predicate(shadowed, false, "*", false, "*", false, "*", false, L4ProtocolTypes.ANY);
//						predicates.add(shpred);
//					}
//				}
//				//Generate and add reconverted predicates
//				for(String shadowed: shadowedAddressesListDst) {
//					if(!dstList.contains(shadowed)) {
//						Predicate rcvedpred = new Predicate("*", false, shadowed, false, "*", false, "*", false, L4ProtocolTypes.ANY);
//						predicates.add(rcvedpred);
//					}
//				}
//				//Reconversion predicate
//				if(!dstList.contains(node.getName())) {
//					Predicate rcpred = new Predicate("*", false, node.getName(), false, "*", false, "*", false, L4ProtocolTypes.ANY);
//					predicates.add(rcpred);
//				}
//				//Add shadowed predicate: this is enough, all the others have already been added
//				predicates.add(new Predicate(node.getName(), false, "*", false, "*", false, "*", false, L4ProtocolTypes.ANY));	
//			} 
//				//If the node is a firewall, compute its allowed rules list
//				//Algorithm 1 Yang_Lam 2015
//				else if(node.getFunctionalType() == FunctionalTypes.FIREWALL) {
//				
//				List<Predicate> allowedList = new ArrayList<>();
//				List<Predicate> deniedList = new ArrayList<>();
//				
//				boolean deniedListChanged = false;
//				for(Elements rule: node.getConfiguration().getFirewall().getElements()) {
//					if(rule.getAction().equals(ActionTypes.DENY)) {
//						//deny <--- deny V rule-i
//						deniedList.add(new Predicate(rule.getSource(), false, rule.getDestination(), false, 
//								rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol()));
//						deniedListChanged = true;
//					} else {
//						//allowed <--- allowed V (rule-i AND !denied)
//						Predicate toAdd = new Predicate(rule.getSource(), false, rule.getDestination(), false, 
//								rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol());
//						List<Predicate> allowedToAdd = aputils.computeAllowedForRule(toAdd, deniedList, deniedListChanged);
//						for(Predicate allow: allowedToAdd) {
//							if(!aputils.isPredicateContainedIn(allow, allowedList))
//								allowedList.add(allow);
//						}
//					}
//				}
//				//Check default action: if DENY do nothing
//				if(node.getConfiguration().getFirewall().getDefaultAction().equals(ActionTypes.ALLOW)) {
//					Predicate toAdd = new Predicate("*", false, "*", false, "*", false, "*", false, L4ProtocolTypes.ANY);
//					List<Predicate> allowedToAdd = aputils.computeAllowedForRule(toAdd, deniedList, deniedListChanged);
//					for(Predicate allow: allowedToAdd) {
//						if(!aputils.isPredicateContainedIn(allow, allowedList))
//							allowedList.add(allow);
//					}
//				}
//				
//				//Insert allowed list into predicates (with optimization)
//				for(Predicate p: allowedList) {
//					for(IPAddress IPSrc: p.getIPSrcList()) {
//						String ips = IPSrc.toString();
//						if(!srcList.contains(ips)) {
//							srcList.add(ips);
//							predicates.add(new Predicate(ips, false, "*", false, "*", false, "*", false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(IPAddress IPDst: p.getIPDstList()) {
//						String ipd = IPDst.toString();
//						if(!dstList.contains(ipd)) {
//							dstList.add(ipd);
//							predicates.add(new Predicate("*", false, ipd, false, "*", false, "*", false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(PortInterval pSrc: p.getpSrcList()) {
//						String ps = pSrc.toString();
//						if(!srcPList.contains(ps)) {
//							srcPList.add(ps);
//							predicates.add(new Predicate("*", false, "*", false, ps, false, "*", false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(PortInterval pDst: p.getpDstList()) {
//						String pd = pDst.toString();
//						if(!dstPList.contains(pd)) {
//							dstPList.add(pd);
//							predicates.add(new Predicate("*", false, "*", false, "*", false, pd, false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(L4ProtocolTypes proto: p.getProtoTypeList()) {
//						if(!dstProtoList.contains(proto)) {
//							dstProtoList.add(proto);
//							predicates.add(new Predicate("*", false, "*", false, "*", false, "*", false, proto));
//						}
//					}
//				}
//				
//				//the algorithm returns the allowed predicates list (if we want also the denied predicates list, we can compute allowed list negation)
//				allocationNodes.get(node.getName()).setForwardBehaviourPredicateList(allowedList);
//			} else if(node.getFunctionalType() == FunctionalTypes.STATEFUL_FIREWALL) {
//				
//				AllocationNode an  = allocationNodes.get(node.getName());
//				StatefulPacketFilter spf = (StatefulPacketFilter) an.getPlacedNF();
//				
//				
//				List<Predicate> allowedList = new ArrayList<>();
//				List<Predicate> deniedList = new ArrayList<>();
//				int aIndex = 0;
//		   		int dIndex = 0;
//		   		int acIndex = 0;
//				
//				boolean deniedListChanged = false;
//				for(Elements rule: node.getConfiguration().getStatefulFirewall().getElements()) {
//					if(rule.getAction().equals(ActionTypes.DENY)) {
//						//deny <--- deny V rule-i
//						Predicate predicate = new Predicate(rule.getSource(), false, rule.getDestination(), false, 
//								rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol());
//						deniedList.add(predicate);
//						spf.addDenyPredicate(dIndex++, predicate);
//						deniedListChanged = true;
//					} else if (rule.getAction().equals(ActionTypes.ALLOW)) {
//						//allowed <--- allowed V (rule-i AND !denied)
//						Predicate toAdd = new Predicate(rule.getSource(), false, rule.getDestination(), false, 
//								rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol());
//						List<Predicate> allowedToAdd = aputils.computeAllowedForRule(toAdd, deniedList, deniedListChanged);
//						for(Predicate allow: allowedToAdd) {
//							if(!aputils.isPredicateContainedIn(allow, allowedList))
//								allowedList.add(allow);
//						}
//						//spf.addAllowPredicate(aIndex++, toAdd);
//					} else {
//						Predicate predicate = new Predicate(rule.getSource(), false, rule.getDestination(), false, 
//								rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol());
//						Predicate invPredicate = new Predicate(rule.getDestination(), false, rule.getSource(), false, 
//								rule.getDstPort(), false, rule.getSrcPort(), false, rule.getProtocol());
//						if(node.getConfiguration().getStatefulFirewall().getDefaultAction().equals(ActionTypes.DENY)) {
//							List<Predicate> allowedToAdd = aputils.computeAllowedForRule(predicate, deniedList, deniedListChanged);
//							for(Predicate allow: allowedToAdd) {
//								if(!aputils.isPredicateContainedIn(allow, allowedList))
//									allowedList.add(allow);
//							}
//						}
//						spf.addAllowCondPredicate(acIndex, predicate);
//						spf.addAllowCondInvPredicate(acIndex++, invPredicate);
//					}
//				}
//				//Check default action: if DENY do nothing
//				if(node.getConfiguration().getStatefulFirewall().getDefaultAction().equals(ActionTypes.ALLOW)) {
//					Predicate toAdd = new Predicate("*", false, "*", false, "*", false, "*", false, L4ProtocolTypes.ANY);
//					List<Predicate> allowedToAdd = aputils.computeAllowedForRule(toAdd, deniedList, deniedListChanged);
//					for(Predicate allow: allowedToAdd) {
//						if(!aputils.isPredicateContainedIn(allow, allowedList))
//							allowedList.add(allow);
//					}
//				}
//				
//				//Insert allowed list into predicates (with optimization)
//				for(Predicate p: allowedList) {
//					
//					//insert allowed list in the map of SPF
//					spf.addAllowPredicate(aIndex++, p);
//					
//					
//					for(IPAddress IPSrc: p.getIPSrcList()) {
//						String ips = IPSrc.toString();
//						if(!srcList.contains(ips)) {
//							srcList.add(ips);
//							predicates.add(new Predicate(ips, false, "*", false, "*", false, "*", false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(IPAddress IPDst: p.getIPDstList()) {
//						String ipd = IPDst.toString();
//						if(!dstList.contains(ipd)) {
//							dstList.add(ipd);
//							predicates.add(new Predicate("*", false, ipd, false, "*", false, "*", false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(PortInterval pSrc: p.getpSrcList()) {
//						String ps = pSrc.toString();
//						if(!srcPList.contains(ps)) {
//							srcPList.add(ps);
//							predicates.add(new Predicate("*", false, "*", false, ps, false, "*", false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(PortInterval pDst: p.getpDstList()) {
//						String pd = pDst.toString();
//						if(!dstPList.contains(pd)) {
//							dstPList.add(pd);
//							predicates.add(new Predicate("*", false, "*", false, "*", false, pd, false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(L4ProtocolTypes proto: p.getProtoTypeList()) {
//						if(!dstProtoList.contains(proto)) {
//							dstProtoList.add(proto);
//							predicates.add(new Predicate("*", false, "*", false, "*", false, "*", false, proto));
//						}
//					}
//				}
//				
//				//Insert predicates related to the "conditional allow" rules
//				List<Predicate> mergedList = new ArrayList<>();
//				mergedList.addAll(spf.getAllowCondPredicates().values());
//				mergedList.addAll(spf.getAllowCondInvPredicates().values());
//				for(Predicate p : mergedList) {
//					for(IPAddress IPSrc: p.getIPSrcList()) {
//						String ips = IPSrc.toString();
//						if(!srcList.contains(ips)) {
//							srcList.add(ips);
//							predicates.add(new Predicate(ips, false, "*", false, "*", false, "*", false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(IPAddress IPDst: p.getIPDstList()) {
//						String ipd = IPDst.toString();
//						if(!dstList.contains(ipd)) {
//							dstList.add(ipd);
//							predicates.add(new Predicate("*", false, ipd, false, "*", false, "*", false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(PortInterval pSrc: p.getpSrcList()) {
//						String ps = pSrc.toString();
//						if(!srcPList.contains(ps)) {
//							srcPList.add(ps);
//							predicates.add(new Predicate("*", false, "*", false, ps, false, "*", false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(PortInterval pDst: p.getpDstList()) {
//						String pd = pDst.toString();
//						if(!dstPList.contains(pd)) {
//							dstPList.add(pd);
//							predicates.add(new Predicate("*", false, "*", false, "*", false, pd, false, L4ProtocolTypes.ANY));
//						}
//					}
//					for(L4ProtocolTypes proto: p.getProtoTypeList()) {
//						if(!dstProtoList.contains(proto)) {
//							dstProtoList.add(proto);
//							predicates.add(new Predicate("*", false, "*", false, "*", false, "*", false, proto));
//						}
//					}
//				}
//				
//				//the algorithm returns the allowed predicates list (if we want also the denied predicates list, we can compute allowed list negation)
//				allocationNodes.get(node.getName()).setForwardBehaviourPredicateList(allowedList);
//				
//			}
//		}
//
//		//DEBUG: interesting predicates for requirements source and destination
//		System.out.println("INTERESTING PREDICATES: " + predicates.size());
////		for(Predicate p: predicates)
////			p.print();
//		//END DEBUG
//
//		//Now we have the list of predicates on which we have to compute the set of atomic predicates, so compute atomic predicates
//		atomicPredicates = aputils.computeAtomicPredicates(atomicPredicates, predicates);
//		
//		//Give to each atomic predicate an identifier
//		int index = 0;
//		for(Predicate p: atomicPredicates) {
//			networkAtomicPredicates.put(index, p);
//			index++;
//		}
//		
//		//DEBUG: print atomic predicates
////		System.out.println("ATOMIC PREDICATES " + networkAtomicPredicates.size());
////		for(HashMap.Entry<Integer, Predicate> entry: networkAtomicPredicates.entrySet()) {
////			System.out.print(entry.getKey() + " ");
////			entry.getValue().print();
////		}
//		//END DEBUG
//	
//		return networkAtomicPredicates;
//	}


	/**
	 * For each requirement, this method identifies all the possible the paths of nodes that must be crossed by the traffic flows that are related to the requirement.
	 * @return the map of all the traffic flows
	 */
	private HashMap<Integer, FlowPath> generateFlowPaths(){
		HashMap<Integer, FlowPath> flowsMap = new HashMap<>();
		int id = 0;
		
		for(SecurityRequirement sr : securityRequirements.values()) {
			Property property = sr.getOriginalProperty();
			
			//first, this method finds if a forwarding path has been defined by the user for the requirement
			//in that case, the research is not performed for that specific requirement
			
			Path definedPath = null;
			if(paths != null) {
				for(Path p : paths) {
					String first = p.getPathNode().get(0).getName();
					String last = p.getPathNode().get(p.getPathNode().size()-1).getName();
					if(first.equals(property.getSrc()) && last.equals(property.getDst())) {
						definedPath = p;
					}	
				}
			}
			
			
			boolean found = false;
			List<List<AllocationNode>> allPaths = new ArrayList<>();
			List<AllocationNode> localPath = new ArrayList<>();
			//if no forwarding path has been defined by the user, the framework searches for ALL the possible existing path.
			//for each path, a corresponding flow is defined. The traffic characterization will be made in a different moment.
			if(definedPath == null) {
				Set<String> visited = new HashSet<>();
				AllocationNode source = allocationNodes.get(property.getSrc());
				AllocationNode destination = allocationNodes.get(property.getDst());
				recursivePathGeneration(allPaths, localPath, source, destination, source, visited, 0);
				found = allPaths.isEmpty()? false : true;
				visited.clear();
			}else {
				//otherwise, the nodes of the path are simply put in the list
				found = true;
				for(PathNode pn : definedPath.getPathNode()) {
					AllocationNode an = allocationNodes.get(pn.getName());
					localPath.add(an);
				}
				allPaths.add(localPath);
			}
			
			if(found) {
				for(List<AllocationNode> singlePath : allPaths) {
					FlowPath flow = new FlowPath(sr, singlePath, id);
					flowsMap.put(id, flow);
					sr.getFlowsMap().put(id, flow);
					id++;
				}
				
			} else {
				throw new BadGraphError("There is no path between " + property.getSrc() + " and " + property.getDst(),
						EType.INVALID_SERVICE_GRAPH);
			}
		
		}
		
		return flowsMap;	
	}

	/**
	 * This method is recursively called to generate the path of nodes for each requirement.
	 * @param allPaths it is the list of all the paths that have been computed for the requirement
	 * @param currentPath it is the current path that the method is building 
	 * @param source it is the source of the path
	 * @param destination it is the destination of the path
	 * @param current it is the current node in the recursive visit
	 * @param visited it is a list of nodes that have been already visited
	 * @param level it is the recursion level of the visit
	 * @return true if a path has been identified, false otherwise
	 */
	private void recursivePathGeneration(List<List<AllocationNode>> allPaths, List<AllocationNode> currentPath, AllocationNode source,
			AllocationNode destination, AllocationNode current, Set<String> visited, int level) {
		
		currentPath.add(level, current);
		visited.add(current.getNode().getName());
		List<Neighbour> listNeighbours = current.getNode().getNeighbour();
		if(destination.getNode().getName().equals(current.getNode().getName())) {
			//I save the completed path and search for others
			List<AllocationNode> pathToStore = new ArrayList<>();
			for(int i = 0; i < currentPath.size(); i++) {
				if((currentPath.get(i).getNode().getFunctionalType() == FunctionalTypes.NAT 
						|| currentPath.get(i).getNode().getFunctionalType() == FunctionalTypes.FIREWALL
						|| currentPath.get(i).getNode().getFunctionalType() == FunctionalTypes.STATEFUL_FIREWALL)
						&& !transformersNode.containsKey(currentPath.get(i).getNode().getName()))
					transformersNode.put(currentPath.get(i).getNode().getName(), currentPath.get(i).getNode());
				pathToStore.add(i, currentPath.get(i));
			}
			allPaths.add(pathToStore);
			visited.remove(current.getNode().getName());
			currentPath.remove(level);
			return;
		}
		if(level != 0) {
			if(current.getNode().getFunctionalType() == FunctionalTypes.WEBCLIENT || current.getNode().getFunctionalType() == FunctionalTypes.WEBSERVER) {
				//traffic is not forwarded anymore
				visited.remove(current.getNode().getName());
				currentPath.remove(level);
				return;
			}
		}
		
		

		for(Neighbour n : listNeighbours) {
			if(!visited.contains(n.getName())) {
				AllocationNode neighbourNode = allocationNodes.get(n.getName());
				level++;
				recursivePathGeneration(allPaths, currentPath, source, destination, neighbourNode, visited, level);
				level--;
			}
					
		}
		
		visited.remove(current.getNode().getName());
		currentPath.remove(level);
		return;
	}

	/**
	 * @return all the allocation nodes
	 */
	public Map<String, AllocationNode> getAllocationNodes() {
		return allocationNodes;
	}

	
	/**
	 * @return all the requirements
	 */
	public Map<Integer, FlowPath> getTrafficFlowsMap(){
		return trafficFlowsMap;
	}

	public List<Property> getProperties() {
		return properties;
	}

	public List<Path> getPaths() {
		return paths;
	}

	public HashMap<Integer, SecurityRequirement> getSecurityRequirements() {
		return securityRequirements;
	}

	public List<Node> getNodes() {
		return nodes;
	}

	public APUtils getAputils() {
		return aputils;
	}


	public HashMap<String, Node> getTransformersNode() {
		return transformersNode;
	}

	public HashMap<String, TestResults> getTestResults() {
		return firewallTestResults;
	}
	
	
}
