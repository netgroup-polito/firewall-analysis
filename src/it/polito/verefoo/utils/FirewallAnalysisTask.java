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
import it.polito.verefoo.graph.Predicate;
import it.polito.verefoo.graph.PredicateRange;
import it.polito.verefoo.jaxb.ActionTypes;
import it.polito.verefoo.jaxb.Elements;
import it.polito.verefoo.jaxb.Node;

public class FirewallAnalysisTask implements Runnable {
	
	Node node;
	APUtils aputils;
	HashMap<String, FW> firewalls;
	
	public FirewallAnalysisTask(Node node, HashMap<String, FW> firewalls, APUtils aputils) {
		this.node = node;
		this.aputils = aputils;
		this.firewalls = firewalls;
	}
	

	@Override
	public void run() {
		FW fw = new FW(node.getName());
		
		/* COMPUTE FIREWALL ATOMIC PREDICATES */
		List<Predicate> predicates = new ArrayList<>();
		List<Predicate> atomicPredicates = new ArrayList<>();
		HashMap<Integer, Predicate> firewallAtomicPredicates = new HashMap<>();
		
		for(Elements rule: node.getConfiguration().getFirewall().getElements()) {
			Predicate newp = new Predicate(rule.getSource(), false, rule.getDestination(), false, 
					rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol());
			predicates.add(newp);
		}
		
		//Starting from this list of predicates we can compute the corresponding set of Atomic Predicates
		atomicPredicates = aputils.computeAtomicPredicates(atomicPredicates, predicates);
		
		//Assign to each Atomic Predicate an identifier
		int index = 0;
		for(Predicate p: atomicPredicates) {
			firewallAtomicPredicates.put(index, p);
			index++;
		}
		
		fw.setFirewallAtomicPredicates(firewallAtomicPredicates);
		
		
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
		
		/* SOLVE FIREWALL ANOMALIES */
		
		/* Priority first:
		 * Ordino le regole all'interno del firewall per priorità. Scansiono una regola per volta e un suo ap per volta.
		 * Se l'ap è già presente in una delle due liste, allowed o denied, non faccio nulla
		 * Altrimenti lo inserisco nella lista corrsipondente in base all'azione della regola
		 */
		
		Collections.sort(atomicRules); // rules sorted by priority, probably it is superfluous
		
		SortedSet<Integer> PFAllowedAPs = new TreeSet<>();
		SortedSet<Integer> PFDeniedAPs = new TreeSet<>();

		for (AtomicRule rule : atomicRules) {
			boolean inAllowed = false;
			boolean inDenied = false;
			List<Predicate> allowedRulePredicates = new ArrayList<>();
			List<Predicate> deniedRulePredicates = new ArrayList<>();
			
			
			for (int ap : rule.getAtomicPredicates()) {
				if(PFDeniedAPs.contains(ap)) {
					inDenied = true;
				} else if(PFAllowedAPs.contains(ap)) {
					inAllowed = true;
				} else {
					if (rule.getAction().equals(ActionTypes.DENY)) {
						PFDeniedAPs.add(ap);
						deniedRulePredicates.add(fw.getAtomicPredicate(ap));
						inDenied = true;
					} else {
						PFAllowedAPs.add(ap);
						allowedRulePredicates.add(fw.getAtomicPredicate(ap));
						inAllowed = true;
					}
				}	
			}
			
			if(inDenied && inAllowed) {
				//The original rule has been split
				fw.addPFAllowedPredicates(allowedRulePredicates);
				fw.addPFDeniedPredicates(deniedRulePredicates);
			} else if (inDenied) {
				fw.addPFDeniedPredicate(rule.getOriginalPredicate());
			} else if(inAllowed) {
				fw.addPFAllowedPredicate(rule.getOriginalPredicate());
			}
		}

		fw.setPFAllowedAPs(PFAllowedAPs);
		fw.setPFDeniedAPs(PFDeniedAPs);
		
		
		/* Allow First:
		 * Scansiono prima tutte le regole ALLOW e inserisco i loro ap all'interno della lista allowed (se non sono già presenti).
		 * Poi scansiono le regole DENY e aggiungo a denied gli ap che non sono già presenti in allowed
		*/

		SortedSet<Integer> AFAllowedAPs = new TreeSet<>();
		SortedSet<Integer> AFDeniedAPs = new TreeSet<>();

		for(AtomicRule rule: atomicRules) {
			if(rule.getAction().equals(ActionTypes.ALLOW)) {
				fw.addAFAllowedPredicate(rule.getOriginalPredicate());
				for(int ap: rule.getAtomicPredicates()) {
					if(!AFAllowedAPs.contains(ap))
						AFAllowedAPs.add(ap);
				}
			}
		}

		for(AtomicRule rule: atomicRules) {
			if(rule.getAction().equals(ActionTypes.DENY)) {
				List<Predicate> deniedRulePredicates = new ArrayList<>();
				boolean split = false;
				for(int ap: rule.getAtomicPredicates()) {
					if(AFAllowedAPs.contains(ap)) {
						split = true;
					} else if(!AFDeniedAPs.contains(ap)) {
						AFDeniedAPs.add(ap);
						deniedRulePredicates.add(fw.getAtomicPredicate(ap));
					}
				}
				if(split) {
					fw.addAFDeniedPredicates(deniedRulePredicates);
				} else {
					//Not split, so insert the original rule
					fw.addAFDeniedPredicate(rule.getOriginalPredicate());
				}
			}
		}

		fw.setAFAllowedAPs(AFAllowedAPs);
		fw.setAFDeniedAPs(AFDeniedAPs);
		
		
		/* Deny First: stesso ragionamento di Allow first */
		
		SortedSet<Integer> DFAllowedAPs = new TreeSet<>();
		SortedSet<Integer> DFDeniedAPs = new TreeSet<>();
		
		for(AtomicRule rule: atomicRules) {
			if(rule.getAction().equals(ActionTypes.DENY)) {
				fw.addDFDeniedPredicate(rule.getOriginalPredicate());
				for(int ap: rule.getAtomicPredicates()) {
					if(!DFDeniedAPs.contains(ap))
						DFDeniedAPs.add(ap);
				}
			}
		}
		
		for(AtomicRule rule: atomicRules) {
			if(rule.getAction().equals(ActionTypes.ALLOW)) {
				List<Predicate> allowedRulePredicates = new ArrayList<>();
				boolean split = false;
				for(int ap: rule.getAtomicPredicates()) {
					if(DFDeniedAPs.contains(ap)) {
						split = true;
					} else if(!DFAllowedAPs.contains(ap)) {
						DFAllowedAPs.add(ap);
						allowedRulePredicates.add(fw.getAtomicPredicate(ap));
					}
				}
				if(split) {
					fw.addDFAllowedPredicates(allowedRulePredicates);
				} else {
					//Not split, so insert the original rule
					fw.addDFAllowedPredicate(rule.getOriginalPredicate());
				}
			}
		}
		
		fw.setDFAllowedAPs(DFAllowedAPs);
		fw.setDFDeniedAPs(DFDeniedAPs);
		
		
		
		/* MERGE PREDICATES PROCESS */
		
		/* Priority First */
		
		/* DENIED */
		for(Predicate ap: fw.getPFDeniedPredicates()) {
			SortedSet<IPAddressRange> PFDeniedSetIPSrcs = new TreeSet<>();
			SortedSet<IPAddressRange> PFDeniedSetIPDsts = new TreeSet<>();
			
			for(IPAddress ip: ap.getIPSrcList()) {
				IPAddressRange iprange = new IPAddressRange(ip);
				PFDeniedSetIPSrcs.add(iprange);
			}
			
			for(IPAddress ip: ap.getIPDstList()) {
				IPAddressRange iprange = new IPAddressRange(ip);
				PFDeniedSetIPDsts.add(iprange);
			}
			
			//DEBUG: print IPAddressRange in AND
//			System.out.println("HERE PREDICATE");
//			ap.print();
//			System.out.print("\nSources: ");
//			for(IPAddressRange ipr: PFDeniedSetIPSrcs)
//				System.out.print(ipr + " ");
//			System.out.println();
//			
//			System.out.print("Destinations: ");
//			for(IPAddressRange ipr: PFDeniedSetIPDsts)
//				System.out.print(ipr + " ");
//			System.out.println();
			//END DEBUG
			
			//chiama la funzione che fa merge, ovvero che trasforma gli IPAddressRanges nella lista da AND a OR
			PredicateRange prange = new PredicateRange();
			prange.setIPSrcList(PFDeniedSetIPSrcs);
			prange.setIPDstList(PFDeniedSetIPDsts);
			
			
			
		}
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		firewalls.put(node.getName(), fw);

	}

}
