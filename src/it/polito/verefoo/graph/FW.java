package it.polito.verefoo.graph;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

public class FW {
	String name;
	
	List<AtomicRule> atomicRules;
	
	SortedSet<Integer> allowedAPs;
	SortedSet<Integer> deniedAPs;
	
	List<Predicate> allowedPredicates = new ArrayList<>();
	List<Predicate> deniedPredicates = new ArrayList<>();
	
	List<PredicateRange> allowedPredicatesRange = new ArrayList<>();
	List<PredicateRange> deniedPredicatesRange = new ArrayList<>();
	
	private HashMap<Integer, Predicate> firewallAtomicPredicates = new HashMap<>();
	
	public FW(String name) {
		this.name = name;
	}
	
	
	public HashMap<Integer, Predicate> getFirewallAtomicPredicates() {
		return firewallAtomicPredicates;
	}

	public void setFirewallAtomicPredicates(HashMap<Integer, Predicate> firewallAtomicPredicates) {
		this.firewallAtomicPredicates = firewallAtomicPredicates;
	}

	public void setAtomicRules(List<AtomicRule> atomicRules) {
		this.atomicRules = atomicRules;
	}

	public List<AtomicRule> getAtomicRules() {
		return atomicRules;
	}
	
	public void addDeniedPredicateRange(PredicateRange prange) {
		deniedPredicatesRange.add(prange);
	}
	
	public void addAllowedPredicateRange(PredicateRange prange) {
		allowedPredicatesRange.add(prange);
	}
	
	public SortedSet<Integer> getAllowedAPs() {
		return allowedAPs;
	}

	public void setAllowedAPs(SortedSet<Integer> allowedAPs) {
		this.allowedAPs = allowedAPs;
	}

	public SortedSet<Integer> getDeniedAPs() {
		return deniedAPs;
	}

	public void setDeniedAPs(SortedSet<Integer> deniedAPs) {
		this.deniedAPs = deniedAPs;
	}

	public void addAllowedPredicates(List<Predicate> list) {
		allowedPredicates.addAll(list);
	}
	
	public void addDeniedPredicates(List<Predicate> list) {
		deniedPredicates.addAll(list);
	}
	
	public void addAllowedPredicate(Predicate pred) {
		allowedPredicates.add(pred);
	}
	
	public void addDeniedPredicate(Predicate pred) {
		deniedPredicates.add(pred);
	}

	public List<Predicate> getAllowedPredicates(){
		return allowedPredicates;
	}
	
	public List<Predicate> getDeniedPredicates(){
		return deniedPredicates;
	}
	
	public String getName() {
		return name;
	}
	
	public List<PredicateRange> getAllowedPredicatesRange() {
		return allowedPredicatesRange;
	}

	public List<PredicateRange> getDeniedPredicatesRange() {
		return deniedPredicatesRange;
	}


	public Predicate getAtomicPredicate(int id) {
		if(firewallAtomicPredicates.containsKey(id)) {
			return firewallAtomicPredicates.get(id);
		}
		return null;
	}
	
}
