package it.polito.verefoo.utils;

public class Range implements Comparable<Range>{
	
	int min;
	int max;
	
	public Range(String s) {
		if(s.equals("-1")) {
			min = 0;
			max = 255;
		} else {
			min = Integer.valueOf(s);
			max = Integer.valueOf(s);
		}
	}
	
	public int getMin() {
		return min;
	}

	public int getMax() {
		return max;
	}

	@Override
	public String toString() {
		return min == max ? String.valueOf(min) : String.valueOf(min)+"-"+String.valueOf(max);
	}

	@Override
	public int compareTo(Range o) {
		return min - o.getMin();
	}
}
