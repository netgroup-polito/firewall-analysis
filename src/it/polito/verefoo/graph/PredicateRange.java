package it.polito.verefoo.graph;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import it.polito.verefoo.jaxb.L4ProtocolTypes;
import it.polito.verefoo.utils.Range;

public class PredicateRange implements Comparable<PredicateRange>{
	
	SortedSet<IPAddressRange> IPSrcList; //in OR
	SortedSet<IPAddressRange> IPDstList; //in oR
	SortedSet<Range> pSrcList; //in OR
	SortedSet<Range> pDstList; //in OR
	List<L4ProtocolTypes> protoTypeList; //in OR
	
	public PredicateRange() {
	}
	
	public void setIPSrcList(SortedSet<IPAddressRange> list) {
		//The list in input contains IPAddress Ranges in AND -> transformed in OR
		IPSrcList = fromANDtoORIPAddressRange(list);
		
		//DEBUG: print IPAddressRange in OR
//		System.out.println("NEW IP SOURCE LIST");
//		for(IPAddressRange ip: IPSrcList)
//			System.out.print(ip + ", ");
//		System.out.println();
		//END DEBUG
	}
	
	public void setIPDstList(SortedSet<IPAddressRange> list) {
		//The list in input contains IPAddress Ranges in AND -> transformed in OR
		IPDstList = fromANDtoORIPAddressRange(list);
	}
	
	public SortedSet<IPAddressRange> getIPSrcList() {
		return IPSrcList;
	}

	public SortedSet<IPAddressRange> getIPDstList() {
		return IPDstList;
	}
	
	public SortedSet<IPAddressRange> fromANDtoORIPAddressRange(SortedSet<IPAddressRange> list){
		SortedSet<IPAddressRange> ORList = new TreeSet<>();
		
		//First in the list is the positive one
		ORList.add(list.first());
		Iterator<IPAddressRange> it = list.iterator();
		it.next();
	
		while(it.hasNext()) {
			IPAddressRange next = it.next();
			SortedSet<IPAddressRange> newORList = new TreeSet<>();
			
			for(IPAddressRange ipar:ORList) {
				if(next.isIncludedIn(ipar)) {
					//split happens between next and ipar
					split(ipar, next, newORList, 1);
				}
				else {
					newORList.add(ipar);
				}
			}
			
			ORList = newORList;
		}
		
		return ORList;
	}
	
	
	//Split the two IPAddress and add the results to list
	public void split(IPAddressRange ipar1, IPAddressRange ipar2, 
			SortedSet<IPAddressRange> list, int bytePosition){
		
		//System.out.println("SPLIT  " +ipar1 + " VERSUS "+ipar2 + "position " + bytePosition);
		if(bytePosition == 5)
			return;
		
		if(ipar1.getByteInPosition(bytePosition).equals(ipar2.getByteInPosition(bytePosition))) {
			//split does not happen in this byte
			split(ipar1, ipar2, list, bytePosition+1);
			return;
		}
		
		Range outer = ipar1.getByteInPosition(bytePosition);
		Range inner = ipar2.getByteInPosition(bytePosition);
		
		if(outer.getMin() != inner.getMin()) {
			//they do not have the same starting point
			IPAddressRange newipar1 = new IPAddressRange();
			
			Range res1 = new Range();
			res1.setMin(outer.getMin());
			if(inner.getMin() >= 1)
				res1.setMax(inner.getMin()-1);
			else res1.setMax(0);
			newipar1.setByteInPosition(bytePosition, res1);
			
			//Bytes in previous + following positions take the value from outer
			for(int i=1; i<5; i++) {
				if(i != bytePosition)
					newipar1.setByteInPosition(i, ipar1.getByteInPosition(i));
			}
			//System.out.println("ADDED "+ newipar1);
			//Last byte cannot be equal to 0
			if(!(newipar1.getFourthByte().getMin() == 0 && newipar1.getFourthByte().getMax() == 0))
				list.add(newipar1);
		}
		
		if(outer.getMax() != inner.getMax()){
			//the do not have the same ending point
			IPAddressRange newipar2 = new IPAddressRange();
			Range res2 = new Range();
			res2.setMin(inner.getMax()+1);
			res2.setMax(outer.getMax());
			newipar2.setByteInPosition(bytePosition, res2);
			
			//Bytes in previous + following positions take the value from outer
			for(int i=1; i<5; i++) {
				if(i != bytePosition)
					newipar2.setByteInPosition(i, ipar1.getByteInPosition(i));
			}
			//System.out.println("ADDED "+ newipar2);
			//Last byte cannot be equal to 0
			if(!(newipar2.getFourthByte().getMin() == 0 && newipar2.getFourthByte().getMax() == 0))
				list.add(newipar2);
		}
		
		
		IPAddressRange newIPAdd = new IPAddressRange();
		for(int i=1; i<5; i++) {
			if(i != bytePosition)
				newIPAdd.setByteInPosition(i, ipar1.getByteInPosition(i));;
		}
		newIPAdd.setByteInPosition(bytePosition, ipar2.getByteInPosition(bytePosition));
		
		split(newIPAdd, ipar2, list, bytePosition+1);	
	}


	public void setpSrcList(SortedSet<Range> pSrcList) {
		this.pSrcList = fromANDtoORPortRange(pSrcList);
		
		//DEBUG: print pSrcRange in OR
//		System.out.println("NEW PORT SOURCE LIST");
//		for(Range r: pSrcList) {
//			System.out.print(r + " ");
//		System.out.println();
//		}
		//END DEBUG
	}

	public void setpDstList(SortedSet<Range> pDstList) {
		this.pDstList = fromANDtoORPortRange(pDstList);
	}
	 
	
	public SortedSet<Range> fromANDtoORPortRange(SortedSet<Range> list){
		SortedSet<Range> ORList = new TreeSet<>();
		
		ORList.add(list.first());
		Iterator<Range> it = list.iterator();
		it.next();
	
		while(it.hasNext()) {
			Range next = it.next();
			SortedSet<Range> newORList = new TreeSet<>();
			
			for(Range r:ORList) {
				if(next.isIncludedIn(r)) {
					//split happens between next and ipar
					splitRange(r, next, newORList);
				}
				else {
					newORList.add(r);
				}
			}
			ORList = newORList;
		}
		return ORList;
	}
	
	public void splitRange(Range r1, Range r2, SortedSet<Range> list) {
		//r1 includes r2
		
		if(r1.getMin() != r2.getMin()) {
			Range newr = new Range(r1.getMin(), r2.getMin()-1);
			list.add(newr);
		}
		
		if(r1.getMax() != r2.getMax()) {
			Range newr2 = new Range(r2.getMax()+1, r1.getMax());
			list.add(newr2);
		}
	}

	public SortedSet<Range> getpSrcList() {
		return pSrcList;
	}

	public SortedSet<Range> getpDstList() {
		return pDstList;
	}

	public List<L4ProtocolTypes> getProtoTypeList() {
		return protoTypeList;
	}

	public void setProtoTypeList(List<L4ProtocolTypes> protoTypeList) {
		List<L4ProtocolTypes> newlist = new ArrayList<>();
		
		for(L4ProtocolTypes p: protoTypeList) {
			if(p.equals(L4ProtocolTypes.ANY)) {
				newlist.add(L4ProtocolTypes.TCP);
				newlist.add(L4ProtocolTypes.UDP);
				newlist.add(L4ProtocolTypes.OTHER);
			} else {
				newlist.add(p);
			}
		}
		
		this.protoTypeList = newlist;
	}

	@Override
	public int compareTo(PredicateRange o) {
		return IPSrcList.first().compareTo(o.getIPSrcList().first());
	}
	
	
	public PredicateRange isContiguousTo(PredicateRange o) {
		
		//Check IPsrc
		
		return null;
	}
	
	
	
	//Just for DEBUG
		public void print() {
			System.out.print(": {");
			int i=0;
			for(IPAddressRange IPSrc: IPSrcList) {
				if(i!=0) System.out.print(" OR ");
				System.out.print(IPSrc);
				i++;
			}
			i=0;
			System.out.print(", ");
			for(Range pSrc: pSrcList) {
				if(i!=0) System.out.print(" OR ");
				System.out.print(pSrc);
				i++;
			}
			i=0;
			System.out.print(", ");
			for(IPAddressRange IPDst: IPDstList) {
				if(i!=0) System.out.print(" OR ");
				System.out.print(IPDst);
				i++;
			}
			i=0;
			System.out.print(", ");
			for(Range pDst: pDstList) {
				if(i!=0) System.out.print(" OR ");
				System.out.print(pDst);
				i++;
			}
			i=0;
			System.out.print(", ");
			for(L4ProtocolTypes proto: protoTypeList) {
				if(i!=0) System.out.print("-");
				System.out.print(proto);
				i++;
			}
			System.out.print("}");
		}

}
