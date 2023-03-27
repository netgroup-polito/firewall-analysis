package it.polito.verefoo.graph;

import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

import it.polito.verefoo.utils.Range;

public class PredicateRange {
	
	SortedSet<IPAddressRange> IPSrcList; //in OR
	SortedSet<IPAddressRange> IPDstList; //in oR
	
	public PredicateRange() {
	}
	
	public void setIPSrcList(SortedSet<IPAddressRange> list) {
		//The list in input contains IPAddress Ranges in AND -> transformed in OR
		IPSrcList = fromANDtoORIPAddressRange(list);
		
		System.out.println("NEW IP SOURCE LIST");
		for(IPAddressRange ip: IPSrcList)
			System.out.print(ip + ", ");
		System.out.println();
	}
	
	public void setIPDstList(SortedSet<IPAddressRange> list) {
		//The list in input contains IPAddress Ranges in AND -> transformed in OR
		IPDstList = fromANDtoORIPAddressRange(list);
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
		
		System.out.println("SPLIT  " +ipar1 + " VERSUS "+ipar2 + "position " + bytePosition);
		
		if(bytePosition == 5)
			return;
		
		if(ipar1.getByteInPosition(bytePosition).equals(ipar2.getByteInPosition(bytePosition))) {
			//split does not happen in this byte
			split(ipar1, ipar2, list, bytePosition+1);
			return;
		}
		
		Range outer = ipar1.getByteInPosition(bytePosition);
		Range inner = ipar2.getByteInPosition(bytePosition);
		
		IPAddressRange newipar1 = new IPAddressRange();
		Range res1 = new Range();
		res1.setMin(outer.getMin());
		res1.setMax(inner.getMin()-1);
		newipar1.setByteInPosition(bytePosition, res1);
		
		//Bytes in previous + following positions take the value from outer
		for(int i=1; i<5; i++) {
			if(i != bytePosition)
				newipar1.setByteInPosition(i, ipar1.getByteInPosition(i));
		}
		System.out.println("ADDED "+ newipar1);
		list.add(newipar1);
		
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
		System.out.println("ADDED "+ newipar2);
		list.add(newipar2);
		
		IPAddressRange newIPAdd = new IPAddressRange();
		for(int i=1; i<5; i++) {
			if(i != bytePosition)
				newIPAdd.setByteInPosition(i, ipar1.getByteInPosition(i));;
		}
		newIPAdd.setByteInPosition(bytePosition, ipar2.getByteInPosition(bytePosition));
		
		split(newIPAdd, ipar2, list, bytePosition+1);	
	}
	 
	
	
}
