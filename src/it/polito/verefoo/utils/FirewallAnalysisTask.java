package it.polito.verefoo.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import it.polito.verefoo.graph.AtomicRule;
import it.polito.verefoo.graph.FW;
import it.polito.verefoo.graph.Predicate;
import it.polito.verefoo.jaxb.ActionTypes;
import it.polito.verefoo.jaxb.Elements;
import it.polito.verefoo.jaxb.L4ProtocolTypes;
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
			for (int ap : rule.getAtomicPredicates()) {
				if (!PFAllowedAPs.contains(ap) && !PFDeniedAPs.contains(ap)) {
					// First time we find this ap -> insert it into allowed or denied, based on rule
					// action
					if (rule.getAction().equals(ActionTypes.DENY))
						PFDeniedAPs.add(ap);
					else
						PFAllowedAPs.add(ap);
				}
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
				for(int ap: rule.getAtomicPredicates()) {
					if(!AFAllowedAPs.contains(ap))
						AFAllowedAPs.add(ap);
				}
			}
		}

		for(AtomicRule rule: atomicRules) {
			if(rule.getAction().equals(ActionTypes.DENY)) {
				for(int ap: rule.getAtomicPredicates()) {
					if(!AFAllowedAPs.contains(ap) && !AFDeniedAPs.contains(ap))
						AFDeniedAPs.add(ap);
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
				for(int ap: rule.getAtomicPredicates()) {
					if(!DFDeniedAPs.contains(ap))
						DFDeniedAPs.add(ap);
				}
			}
		}
		
		for(AtomicRule rule: atomicRules) {
			if(rule.getAction().equals(ActionTypes.ALLOW)) {
				for(int ap: rule.getAtomicPredicates()) {
					if(!DFDeniedAPs.contains(ap) && !DFAllowedAPs.contains(ap))
						DFAllowedAPs.add(ap);
				}
			}
		}
		
		fw.setDFAllowedAPs(DFAllowedAPs);
		fw.setDFDeniedAPs(DFDeniedAPs);
		
		firewalls.put(node.getName(), fw);

	}

}
