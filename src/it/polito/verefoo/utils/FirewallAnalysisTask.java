package it.polito.verefoo.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import it.polito.verefoo.graph.AtomicRule;
import it.polito.verefoo.graph.FW;
import it.polito.verefoo.graph.IPAddress;
import it.polito.verefoo.graph.IPAddressRange;
import it.polito.verefoo.graph.PortInterval;
import it.polito.verefoo.graph.Predicate;
import it.polito.verefoo.graph.PredicateRange;
import it.polito.verefoo.graph.ResolutionStrategy;
import it.polito.verefoo.jaxb.ActionTypes;
import it.polito.verefoo.jaxb.Elements;
import it.polito.verefoo.jaxb.L4ProtocolTypes;
import it.polito.verefoo.jaxb.Node;

public class FirewallAnalysisTask implements Runnable {
	
	Node node;
	APUtils aputils;
	HashMap<String, FW> firewalls;
	ResolutionStrategy strategy;
	TestResults fresult;
	
	public FirewallAnalysisTask(Node node, HashMap<String, FW> firewalls, APUtils aputils, ResolutionStrategy strategy, TestResults fresult) {
		this.node = node;
		this.aputils = aputils;
		this.firewalls = firewalls;
		this.strategy = strategy;
		this.fresult = fresult;
	}
	

	@Override
	public void run() {
		FW fw = new FW(node.getName());
		
		/* COMPUTE FIREWALL ATOMIC PREDICATES */
		long beginAP = System.currentTimeMillis();
		
		List<Predicate> atomicPredicates = new ArrayList<>();
		HashMap<Integer, Predicate> firewallAtomicPredicates = new HashMap<>();
		List<IPAddress> distinctIPSrcList = new ArrayList<>();
		List<IPAddress> distinctIPDstList = new ArrayList<>();
		List<PortInterval> distinctPSrcList = new ArrayList<>();
		List<PortInterval> distinctPDstList = new ArrayList<>();
		List<L4ProtocolTypes> ProtoList = new ArrayList<>();
		
		ProtoList.add(L4ProtocolTypes.ANY);
		
		for(Elements rule: node.getConfiguration().getFirewall().getElements()) {
			
			IPAddress ipsrc = new IPAddress(rule.getSource(), false);
			if(!distinctIPSrcList.contains(ipsrc))
				distinctIPSrcList.add(ipsrc);
			
			IPAddress ipdst = new IPAddress(rule.getDestination(), false);
			if(!distinctIPDstList.contains(ipdst))
				distinctIPDstList.add(ipdst);
			
			PortInterval psrc = new PortInterval(rule.getSrcPort(), false);
			if(!distinctPSrcList.contains(psrc))
				distinctPSrcList.add(psrc);
			
			PortInterval pdst = new PortInterval(rule.getDstPort(), false);
			if(!distinctPDstList.contains(pdst))
				distinctPDstList.add(pdst);
			
		}
		
		//Starting from this list of predicates we can compute the corresponding set of Atomic Predicates
		atomicPredicates = aputils.computeAtomicPredicatesNewAlgorithm(
				aputils.computeAtomicIPAddresses(distinctIPSrcList), aputils.computeAtomicIPAddresses(distinctIPDstList), 
				aputils.computeAtomicPortIntervals(distinctPSrcList), aputils.computeAtomicPortIntervals(distinctPDstList),
				ProtoList);
		
		//Assign to each Atomic Predicate an identifier
		int index = 0;
		for(Predicate p: atomicPredicates) {
			if(!p.hasIPSrcOnlyNegs() && !p.hasIPDstOnlyNegs() 
					&& !p.hasPSrcOnlyNegs() && !p.hasPDstOnlyNegs()) {
				firewallAtomicPredicates.put(index, p);
				index++;
			}
		}
		
		fw.setFirewallAtomicPredicates(firewallAtomicPredicates);
		long endAP = System.currentTimeMillis();
		fresult.setAtomicPredCompTime(endAP - beginAP);
		fresult.setNumberAP(firewallAtomicPredicates.size());
		
		/* REWRITE FIREWALL RULES */
		int count = 1;
		List<AtomicRule> atomicRules = new ArrayList<>();
		
		for(Elements rule: node.getConfiguration().getFirewall().getElements()) {

			Predicate rulePred = new Predicate(rule.getSource(), false, rule.getDestination(), false, 
					rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol());
			
			AtomicRule newAtomicRule = new AtomicRule(rule.getAction(), count, rulePred);
			
			for(HashMap.Entry<Integer, Predicate> apEntry: firewallAtomicPredicates.entrySet()) {
				Predicate intersectionPredicate = aputils.computeIntersection(apEntry.getValue(), rulePred);
				if(intersectionPredicate != null && aputils.APCompare(intersectionPredicate, apEntry.getValue())
						&& !apEntry.getValue().hasIPDstOnlyNegs()) {
					//System.out.print(apEntry.getKey() + " "); apEntry.getValue().print();
					newAtomicRule.addAtomicPredicates(apEntry.getKey());
				}
			}
			count++;
			atomicRules.add(newAtomicRule);
		}
		
		fw.setAtomicRules(atomicRules);
		long endRWR = System.currentTimeMillis();
		fresult.setRewriteRuleCompTime(endRWR - endAP);
		
		/* SOLVE FIREWALL ANOMALIES */
		SortedSet<Integer> allowedAPs = new TreeSet<>();
		SortedSet<Integer> deniedAPs = new TreeSet<>();
		
		/* Priority first:
		 * Ordino le regole all'interno del firewall per priorità. Scansiono una regola per volta e un suo ap per volta.
		 * Se l'ap è già presente in una delle due liste, allowed o denied, non faccio nulla
		 * Altrimenti lo inserisco nella lista corrsipondente in base all'azione della regola
		 */
		
		if(strategy.equals(ResolutionStrategy.PIORITY_FIRST)) {
			
			Collections.sort(atomicRules); // rules sorted by priority, probably it is superfluous
			
			for (AtomicRule rule : atomicRules) {
				boolean inAllowed = false;
				boolean inDenied = false;
				List<Predicate> allowedRulePredicates = new ArrayList<>();
				List<Predicate> deniedRulePredicates = new ArrayList<>();
				
				
				for (int ap : rule.getAtomicPredicates()) {
					if(deniedAPs.contains(ap)) {
						inDenied = true;
					} else if(allowedAPs.contains(ap)) {
						inAllowed = true;
					} else {
						if (rule.getAction().equals(ActionTypes.DENY)) {
							deniedAPs.add(ap);
							deniedRulePredicates.add(fw.getAtomicPredicate(ap));
							inDenied = true;
						} else {
							allowedAPs.add(ap);
							allowedRulePredicates.add(fw.getAtomicPredicate(ap));
							inAllowed = true;
						}
					}	
				}
				
				if(inDenied && inAllowed) {
					//The original rule has been split
					fw.addAllowedPredicates(allowedRulePredicates);
					fw.addDeniedPredicates(deniedRulePredicates);
				} else if (inDenied) {
					fw.addDeniedPredicate(rule.getOriginalPredicate());
				} else if(inAllowed) {
					fw.addAllowedPredicate(rule.getOriginalPredicate());
				}
			}

			fw.setAllowedAPs(allowedAPs);
			fw.setDeniedAPs(deniedAPs);
		}
		
		
		/* Allow First:
		 * Scansiono prima tutte le regole ALLOW e inserisco i loro ap all'interno della lista allowed (se non sono già presenti).
		 * Poi scansiono le regole DENY e aggiungo a denied gli ap che non sono già presenti in allowed
		*/
		else if(strategy.equals(ResolutionStrategy.ALLOW_FIRST)) {
			
			for(AtomicRule rule: atomicRules) {
				if(rule.getAction().equals(ActionTypes.ALLOW)) {
					fw.addAllowedPredicate(rule.getOriginalPredicate());
					for(int ap: rule.getAtomicPredicates()) {
						if(!allowedAPs.contains(ap))
							allowedAPs.add(ap);
					}
				}
			}

			for(AtomicRule rule: atomicRules) {
				if(rule.getAction().equals(ActionTypes.DENY)) {
					List<Predicate> deniedRulePredicates = new ArrayList<>();
					boolean split = false;
					for(int ap: rule.getAtomicPredicates()) {
						if(allowedAPs.contains(ap)) {
							split = true;
						} else if(!deniedAPs.contains(ap)) {
							deniedAPs.add(ap);
							deniedRulePredicates.add(fw.getAtomicPredicate(ap));
						}
					}
					if(split) {
						fw.addDeniedPredicates(deniedRulePredicates);
					} else {
						//Not split, so insert the original rule
						fw.addDeniedPredicate(rule.getOriginalPredicate());
					}
				}
			}

			fw.setAllowedAPs(allowedAPs);
			fw.setDeniedAPs(deniedAPs);
		}
		
		/* Deny First: stesso ragionamento di Allow first */
		else if(strategy.equals(ResolutionStrategy.DENY_FIRST)) {
			
			for(AtomicRule rule: atomicRules) {
				if(rule.getAction().equals(ActionTypes.DENY)) {
					fw.addDeniedPredicate(rule.getOriginalPredicate());
					for(int ap: rule.getAtomicPredicates()) {
						if(!deniedAPs.contains(ap))
							deniedAPs.add(ap);
					}
				}
			}
			
			for(AtomicRule rule: atomicRules) {
				if(rule.getAction().equals(ActionTypes.ALLOW)) {
					List<Predicate> allowedRulePredicates = new ArrayList<>();
					boolean split = false;
					for(int ap: rule.getAtomicPredicates()) {
						if(deniedAPs.contains(ap)) {
							split = true;
						} else if(!allowedAPs.contains(ap)) {
							allowedAPs.add(ap);
							allowedRulePredicates.add(fw.getAtomicPredicate(ap));
						}
					}
					if(split) {
						fw.addAllowedPredicates(allowedRulePredicates);
					} else {
						//Not split, so insert the original rule
						fw.addAllowedPredicate(rule.getOriginalPredicate());
					}
				}
			}
			
			fw.setAllowedAPs(allowedAPs);
			fw.setDeniedAPs(deniedAPs);
			
		}
		
		long endSA = System.currentTimeMillis();
		fresult.setSolveAnomaliesCompTime(endSA - endRWR);
		
		
		/* FROM AND TO OR */
		
		for(Predicate ap: fw.getDeniedPredicates()) {
			fw.addDeniedPredicateRange(fromPredicateToPredicateRange(ap));
		}
		for(Predicate ap: fw.getAllowedPredicates()) {
			fw.addAllowedPredicateRange(fromPredicateToPredicateRange(ap));
		}
		
		long endAndToOr = System.currentTimeMillis();
		fresult.setAndToORCompTime(endAndToOr - endSA);
		
		
		/* MERGE */
		//SortedSet mergedDeniedPredicatesRange = merge(fw.getDeniedPredicatesRange());
		
		
		
		
		firewalls.put(node.getName(), fw);
		long endAll = System.currentTimeMillis();
		fresult.setTotalTime(endAll - beginAP);

	}
	
	
	PredicateRange fromPredicateToPredicateRange(Predicate ap) {
		PredicateRange prange = new PredicateRange();
		
		SortedSet<IPAddressRange> setIPSrcs = new TreeSet<>();
		SortedSet<IPAddressRange> setIPDsts = new TreeSet<>();
		SortedSet<Range> setPSrcs = new TreeSet<>();
		SortedSet<Range> setPDsts = new TreeSet<>();
		
		for(IPAddress ip: ap.getIPSrcList()) {
			IPAddressRange iprange = new IPAddressRange(ip);
			setIPSrcs.add(iprange);
		}
		
		for(IPAddress ip: ap.getIPDstList()) {
			IPAddressRange iprange = new IPAddressRange(ip);
			setIPDsts.add(iprange);
		}
		
		prange.setIPSrcList(setIPSrcs);
		prange.setIPDstList(setIPDsts);
		
		for(PortInterval pi: ap.getpSrcList()) {
			//add and sort
			setPSrcs.add(new Range(pi.getMin(), pi.getMax()));
		}
		prange.setpSrcList(setPSrcs);
		
		for(PortInterval pi: ap.getpDstList()) {
			//add and sort
			setPDsts.add(new Range(pi.getMin(), pi.getMax()));
		}
		prange.setpDstList(setPDsts);
		
		prange.setProtoTypeList(ap.getProtoTypeList());
		
		
		return prange;
	}
	
	
	public SortedSet<PredicateRange> merge(SortedSet<PredicateRange> predicates){
		SortedSet<PredicateRange> newset = new TreeSet<>();
		
		
		
		return newset;
	}

}
