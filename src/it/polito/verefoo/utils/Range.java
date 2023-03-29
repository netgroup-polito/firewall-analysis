package it.polito.verefoo.utils;

public class Range implements Comparable<Range>{
	
	int min;
	int max;
	
	public Range() {
	}
	
	//To use only for Ports
	public Range(int min, int max) {
		if(min == -1 && max == -1) {
			this.min = 0;
			this.max = 65535;
		} else {
			this.min = min;
			this.max = max;
		}
	}
	
	//To use only for IP Address
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
	
	public boolean isContiguousTo(Range o) {
		if(this.min == o.getMax()+1)
			return true;
		else return false;
	}
	
}
