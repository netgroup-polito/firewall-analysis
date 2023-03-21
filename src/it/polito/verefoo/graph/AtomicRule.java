package it.polito.verefoo.graph;

import java.util.SortedSet;
import java.util.TreeSet;

import it.polito.verefoo.jaxb.ActionTypes;

public class AtomicRule implements Comparable<AtomicRule>{
	ActionTypes action;
	SortedSet<Integer> atomicPredicates;
	int priority;
	Predicate originalPredicate;
	boolean apRemoved;
	
	public AtomicRule(ActionTypes action, int priority, Predicate originalPredicate) {
		this.action = action;
		this.priority = priority;
		this.atomicPredicates = new TreeSet<>();
		this.originalPredicate = originalPredicate;
		this.apRemoved = false;
	}
	
	public SortedSet<Integer> getAtomicPredicates() {
		return atomicPredicates;
	}
	public void setAtomicPredicates(SortedSet<Integer> atomicPredicates) {
		this.atomicPredicates = atomicPredicates;
	}
	public ActionTypes getAction() {
		return action;
	}
	public int getPriority() {
		return priority;
	}
	
	public Predicate getOriginalPredicate() {
		return originalPredicate;
	}

	public void addAtomicPredicates(int ap) {
		if(atomicPredicates != null) {
			//Check if already present?
			atomicPredicates.add(ap);
		}
	}
	
	public boolean isApRemoved() {
		return apRemoved;
	}

	public void setApRemoved(boolean apRemoved) {
		this.apRemoved = apRemoved;
	}

	@Override
	public int compareTo(AtomicRule o) {
		return this.priority - o.getPriority();
	}


	public void print() {
		System.out.print("Atomic rule " + this.priority + ", " + this.action);
		this.originalPredicate.print();
		System.out.print(", {");
		for(int ap: this.atomicPredicates)
			System.out.print(ap + " ");
		System.out.println("}");	
	}
	
}
