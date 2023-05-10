package it.polito.verefoo.utils;

public class TestResults {
	private long atomicPredCompTime;
	private long rewriteRuleCompTime;
	private long solveAnomaliesCompTime;
	private long andToORCompTime;
	private long totalTime;
	
	private String z3Result;
	private long totalFlows;
	private long numberAP;
	
	public TestResults() {	
	}

	public long getAtomicPredCompTime() {
		return atomicPredCompTime;
	}

	public void setAtomicPredCompTime(long atomicPredCompTime) {
		this.atomicPredCompTime = atomicPredCompTime;
	}

	public long getRewriteRuleCompTime() {
		return rewriteRuleCompTime;
	}

	public void setRewriteRuleCompTime(long rewriteRuleCompTime) {
		this.rewriteRuleCompTime = rewriteRuleCompTime;
	}

	public long getSolveAnomaliesCompTime() {
		return solveAnomaliesCompTime;
	}

	public void setSolveAnomaliesCompTime(long solveAnomaliesCompTime) {
		this.solveAnomaliesCompTime = solveAnomaliesCompTime;
	}

	public String getZ3Result() {
		return z3Result;
	}

	public void setZ3Result(String z3Result) {
		this.z3Result = z3Result;
	}
	
	public long getTotalFlows() {
		return totalFlows;
	}

	public void setTotalFlows(long totalFlows) {
		this.totalFlows = totalFlows;
	}

	public long getAndToORCompTime() {
		return andToORCompTime;
	}

	public void setAndToORCompTime(long andToORCompTime) {
		this.andToORCompTime = andToORCompTime;
	}

	public long getTotalTime() {
		return totalTime;
	}

	public void setTotalTime(long totalTime) {
		this.totalTime = totalTime;
	}

	public long getNumberAP() {
		return numberAP;
	}

	public void setNumberAP(long numberAP) {
		this.numberAP = numberAP;
	}
}
