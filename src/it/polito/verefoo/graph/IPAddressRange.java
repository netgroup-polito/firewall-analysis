package it.polito.verefoo.graph;

import it.polito.verefoo.utils.Range;

public class IPAddressRange implements Comparable<IPAddressRange>{
	
	Range firstByte;
	Range secondByte;
	Range thirdByte;
	Range fourthByte;
	
	IPAddress original;
	
	public IPAddressRange(IPAddress original) {
		
		this.original = original;
		
		firstByte = new Range(original.getFirstByte());
		secondByte = new Range(original.getSecondByte());
		thirdByte = new Range(original.getThirdByte());
		fourthByte = new Range(original.getFourthByte());
	}
	
	

	public Range getFirstByte() {
		return firstByte;
	}

	public Range getSecondByte() {
		return secondByte;
	}

	public Range getThirdByte() {
		return thirdByte;
	}

	public Range getFourthByte() {
		return fourthByte;
	}

	public IPAddress getOriginal() {
		return original;
	}



	@Override
	public String toString() {
		return new String("[" + firstByte + "].[" + secondByte + "].["
				+ thirdByte + "].[" + fourthByte  + "]");
	}

	@Override
	public int compareTo(IPAddressRange o) {
		if(firstByte.compareTo(o.getFirstByte()) == 0) {
			if(secondByte.compareTo(o.getSecondByte()) == 0) {
				if(thirdByte.compareTo(o.getThirdByte()) == 0) {
					return fourthByte.compareTo(o.getFourthByte());
				}
				return thirdByte.compareTo(o.getThirdByte());
			}
			return secondByte.compareTo(o.getSecondByte());
		}
		
		return firstByte.compareTo(o.getFirstByte());
	}
	
	

}
