package it.polito.verefoo.graph;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.SortedSet;

public class FW {
	String name;
	
	List<AtomicRule> atomicRules;
	
	SortedSet<Integer> PFAllowedAPs;
	SortedSet<Integer> PFDeniedAPs;
	SortedSet<Integer> AFAllowedAPs;
	SortedSet<Integer> AFDeniedAPs;
	SortedSet<Integer> DFAllowedAPs;
	SortedSet<Integer> DFDeniedAPs;
	
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
	
	
	
}
