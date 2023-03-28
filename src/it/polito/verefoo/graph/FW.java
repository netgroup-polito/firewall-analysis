package it.polito.verefoo.graph;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

public class FW {
	String name;
	
	List<AtomicRule> atomicRules;
	
	SortedSet<Integer> PFAllowedAPs;
	SortedSet<Integer> PFDeniedAPs;
	SortedSet<Integer> AFAllowedAPs;
	SortedSet<Integer> AFDeniedAPs;
	SortedSet<Integer> DFAllowedAPs;
	SortedSet<Integer> DFDeniedAPs;
	
	List<Predicate> PFAllowedPredicates = new ArrayList<>();
	List<Predicate> PFDeniedPredicates = new ArrayList<>();
	List<Predicate> AFAllowedPredicates = new ArrayList<>();
	List<Predicate> AFDeniedPredicates = new ArrayList<>();
	List<Predicate> DFAllowedPredicates = new ArrayList<>();
	List<Predicate> DFDeniedPredicates = new ArrayList<>();
	
	SortedSet<PredicateRange> PFAllowedPredicatesRange = new TreeSet<>();
	SortedSet<PredicateRange> PFDeniedPredicatesRange = new TreeSet<>();
	SortedSet<PredicateRange> AFAllowedPredicatesRange = new TreeSet<>();
	SortedSet<PredicateRange> AFDeniedPredicatesRange = new TreeSet<>();
	SortedSet<PredicateRange> DFAllowedPredicatesRange = new TreeSet<>();
	SortedSet<PredicateRange> DFDeniedPredicatesRange = new TreeSet<>();
	
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

	public SortedSet<Integer> getPFAllowedAPs() {
		return PFAllowedAPs;
	}

	public void setPFAllowedAPs(SortedSet<Integer> pFAllowedAPs) {
		PFAllowedAPs = pFAllowedAPs;
	}

	public SortedSet<Integer> getPFDeniedAPs() {
		return PFDeniedAPs;
	}

	public void setPFDeniedAPs(SortedSet<Integer> pFDeniedAPs) {
		PFDeniedAPs = pFDeniedAPs;
	}

	public SortedSet<Integer> getAFAllowedAPs() {
		return AFAllowedAPs;
	}

	public void setAFAllowedAPs(SortedSet<Integer> aFAllowedAPs) {
		AFAllowedAPs = aFAllowedAPs;
	}

	public SortedSet<Integer> getAFDeniedAPs() {
		return AFDeniedAPs;
	}

	public void setAFDeniedAPs(SortedSet<Integer> aFDeniedAPs) {
		AFDeniedAPs = aFDeniedAPs;
	}

	public SortedSet<Integer> getDFAllowedAPs() {
		return DFAllowedAPs;
	}

	public void setDFAllowedAPs(SortedSet<Integer> dFAllowedAPs) {
		DFAllowedAPs = dFAllowedAPs;
	}

	public SortedSet<Integer> getDFDeniedAPs() {
		return DFDeniedAPs;
	}

	public void setDFDeniedAPs(SortedSet<Integer> dFDeniedAPs) {
		DFDeniedAPs = dFDeniedAPs;
	}

	public String getName() {
		return name;
	}
	
	public void addPFAllowedPredicates(List<Predicate> list) {
		PFAllowedPredicates.addAll(list);
	}
	
	public void addPFDeniedPredicates(List<Predicate> list) {
		PFDeniedPredicates.addAll(list);
	}
	
	public void addPFAllowedPredicate(Predicate pred) {
		PFAllowedPredicates.add(pred);
	}
	
	public void addPFDeniedPredicate(Predicate pred) {
		PFDeniedPredicates.add(pred);
	}
	
	public void addAFAllowedPredicates(List<Predicate> list) {
		AFAllowedPredicates.addAll(list);
	}
	
	public void addAFDeniedPredicates(List<Predicate> list) {
		AFDeniedPredicates.addAll(list);
	}
	
	public void addAFAllowedPredicate(Predicate pred) {
		AFAllowedPredicates.add(pred);
	}
	
	public void addAFDeniedPredicate(Predicate pred) {
		AFDeniedPredicates.add(pred);
	}
	
	public void addDFAllowedPredicates(List<Predicate> list) {
		DFAllowedPredicates.addAll(list);
	}
	
	public void addDFDeniedPredicates(List<Predicate> list) {
		DFDeniedPredicates.addAll(list);
	}
	
	public void addDFAllowedPredicate(Predicate pred) {
		DFAllowedPredicates.add(pred);
	}
	
	public void addDFDeniedPredicate(Predicate pred) {
		DFDeniedPredicates.add(pred);
	}
	
	
	public Predicate getAtomicPredicate(int id) {
		if(firewallAtomicPredicates.containsKey(id)) {
			return firewallAtomicPredicates.get(id);
		}
		return null;
	}
	
	public List<Predicate> getPFAllowedPredicates(){
		return PFAllowedPredicates;
	}
	
	public List<Predicate> getPFDeniedPredicates(){
		return PFDeniedPredicates;
	}
	
	public List<Predicate> getAFAllowedPredicates(){
		return AFAllowedPredicates;
	}
	
	public List<Predicate> getAFDeniedPredicates(){
		return AFDeniedPredicates;
	}
	
	public List<Predicate> getDFAllowedPredicates(){
		return DFAllowedPredicates;
	}
	
	public List<Predicate> getDFDeniedPredicates(){
		return DFDeniedPredicates;
	}
	
	public void addPFDeniedPredicateRange(PredicateRange prange) {
		PFDeniedPredicatesRange.add(prange);
	}
	
	public void addPFAllowedPredicateRange(PredicateRange prange) {
		PFAllowedPredicatesRange.add(prange);
	}

	public void addAFDeniedPredicateRange(PredicateRange prange) {
		AFDeniedPredicatesRange.add(prange);
	}
	
	public void addAFAllowedPredicateRange(PredicateRange prange) {
		AFAllowedPredicatesRange.add(prange);
	}
	
	public void addDFDeniedPredicateRange(PredicateRange prange) {
		DFDeniedPredicatesRange.add(prange);
	}
	
	public void addDFAllowedPredicateRange(PredicateRange prange) {
		DFAllowedPredicatesRange.add(prange);
	}
	
}
