package it.polito.verefoo.utils;

public class Range implements Comparable<Range>{
	
	int min;
	int max;
	
	public Range() {
	}
	
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

	public void setMin(int min) {
		this.min = min;
	}

	public void setMax(int max) {
		this.max = max;
	}

	@Override
	public String toString() {
		return min == max ? String.valueOf(min) : "["+String.valueOf(min)+"-"+String.valueOf(max)+"]";
	}

	@Override
	public int compareTo(Range o) {
		return min - o.getMin();
	}

	//true if this is included in other
	public boolean isIncludedIn(Range other) {
		if(other.getMax() >= this.max && other.getMin() <= this.min)
			return true;
		return false;
	}

	@Override
	public boolean equals(Object obj) {
		Range r = (Range) obj;
		if(this.min == r.getMin() && this.max == r.getMax())
			return true;
		
		return false;
	}
	
	
	
}
