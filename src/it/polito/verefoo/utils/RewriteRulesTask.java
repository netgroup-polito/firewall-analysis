package it.polito.verefoo.utils;

import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import it.polito.verefoo.graph.AtomicRule;
import it.polito.verefoo.graph.Predicate;
import it.polito.verefoo.jaxb.Elements;

public class RewriteRulesTask implements Runnable {
	
	int ruleIndex;
	List<Elements> complexRules;
	ConcurrentHashMap<Integer, AtomicRule> atomicRules;
	HashMap<Integer, Predicate> firewallAtomicPredicates;
	APUtils aputils = new APUtils();
	
	
	public RewriteRulesTask(int beginIndex, List<Elements> complexRules,
			ConcurrentHashMap<Integer, AtomicRule> atomicRules, HashMap<Integer, Predicate> firewallAtomicPredicates) {
		super();
		this.ruleIndex = beginIndex + 1; //atomic rules from 1 to nrules (and not 0 to nrules-1)
		this.complexRules = complexRules;
		this.atomicRules = atomicRules;
		this.firewallAtomicPredicates = firewallAtomicPredicates; 
	}



	@Override
	public void run() {
		
		for(Elements rule: complexRules) {

			Predicate rulePred = new Predicate(rule.getSource(), false, rule.getDestination(), false, 
					rule.getSrcPort(), false, rule.getDstPort(), false, rule.getProtocol());
			
			AtomicRule newAtomicRule = new AtomicRule(rule.getAction(), ruleIndex, rulePred);
			
			for(HashMap.Entry<Integer, Predicate> apEntry: firewallAtomicPredicates.entrySet()) {
				if(aputils.isIncludedPredicateNew(apEntry.getValue(), rulePred)) {
					newAtomicRule.addAtomicPredicates(apEntry.getKey());
				}
			}
			
			atomicRules.putIfAbsent(ruleIndex, newAtomicRule);
			ruleIndex++;
		}
		
	}

}
