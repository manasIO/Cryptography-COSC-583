package crpyto;
import java.util.Scanner;
import java.util.Random;

public class SHA1attack {

public static int mlen;
static int K1;
static int K2;
static int K3;
static int K4;
static int H0;
static int H1;
static int H2;
static int H3;
static int H4;
static int flag=0;

	public static int ROTL(int x,int bit) {
		return ((x<<bit) | (x>>>(32-bit)));
	}
    
    public static void main(String[] args){
        
        System.out.println("Enter input text...");
        Scanner sc = new Scanner(System.in);
        String message = sc.nextLine();
        System.out.println("Enter bits...");
        int bits = sc.nextInt();
		
		K1 = 0x5A827999;
		K2 = 0X6ED9EBA1;
		K3 = 0X8F1BBCDC;
		K4 = 0XCA62C1D6;
		H0 = 0X67452301;
		H1 = 0XEFCDAB89;
		H2 = 0X98BADCFE;
		H3 = 0X10325476;
		H4 = 0XC3D2E1F0;
        
        String str = stringToBinary(message);
        String res = padding(message,str,bits);
		//System.out.println("Hash : "+res);
		
		checkCollision(res, bits);
    }

	public static String getSaltString(){ 
		String saltChars = "abcdefghijklmnopqrstuvwxyz1234567890";
		StringBuilder salt = new StringBuilder();
		Random rand = new Random();
		while(salt.length()<2){
			int index = (int)(rand.nextFloat()*saltChars.length());
			salt.append(saltChars.charAt(index));
		}
		return salt.toString();
	}

	public static void checkCollision(String res0, int bits){ 			
			int count = 0;
			res0 = stringToBinary(res0);
			String res1 = "";
			String randStr = "abef";
			while(true){
				String str = stringToBinary(randStr);
				res1 = padding(randStr, str, bits);
				//System.out.println(res1);
				res1 = stringToBinary(res1);
				int i,t=0;
				for(i=0;i<bits;i++){
					if(res0.charAt(i)==res1.charAt(i)){
						t++;
					}
				}
				if(t==bits){
					break;
				}
				randStr = res1;
				count++;				
			}
			System.out.println("Attempts : "+count);
			System.out.println("Collision found!");
			//System.out.println(res0);
			//System.out.println(res1);
	}
	
    
    public static String createMessage(String message, String addOne, int zero, String len,int bits) {
    	StringBuilder strB = new StringBuilder(message);
    	strB.insert(strB.toString().length(),addOne);
    	
    	while(zero>0) {
    		strB.insert(strB.toString().length(),0);
    		zero--;
    	}
    	strB.insert(strB.toString().length(), len);
    	String res = strB.toString();
    	res = res.replaceAll("\\s+","");
    	int[] arr = new int[res.toString().length()/32];
    	
    	for(int i=0;i<res.toString().length();i+=32) {
    		arr[i/32] = Integer.valueOf(res.substring(i+1,i+32),2);
    		if(res.charAt(i)=='1') {
    			arr[i/32] |= 0x80000000;
    		}
    	}
    	String res1 = hash(arr,bits);
		return res1;
    }
    
    public static String stringToBinary(String input){
        byte[] bytes = input.getBytes();  
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes){
            int val = b;
            for(int i=0;i<8;i++){
                sb.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }
            sb.append(' ');
			//System.out.println(sb);
        }
        return sb.toString();
    }
       
    public static String padding(String input, String message,int bits){
        int len = input.length() * 8 - 8;
        String len2 = addZeros(len+8);
        int temp = (len)%512;
        if(432-temp<0) {
        	int a = 512 - temp;
        	temp = a + 440 + temp + 64;
	    }else {
	    	temp = 432 - temp;
	    }
		//System.out.println(temp);
        int zeros = temp;
        String add = "10000000";
        message = message.replaceAll("\\s+",""); 
        return createMessage(message,add,zeros,len2,bits);
    }
    
    public static String addZeros(int val) {
    	String strlen = Integer.toBinaryString(val);
    	StringBuilder strB = new StringBuilder(strlen);
    	int temp = 64-strlen.length();
    	
    	while(temp>0) {
    		strB.insert(0, 0);
    		temp--;
    	}
    	return strB.toString();
    }
     
    public static String hash(int[] m,int bits) {
    	int len = m.length;
    	int[] arr = new int[80];
    	
    	for(int i=0;i<len;i+=16) {
    		for(int j=0;j<=15;j++) {
    			arr[j] = m[j+i];
    		}
    		for(int j=16;j<=79;j++) {
    			arr[j] = ROTL(arr[j-3] ^ arr[j-8] ^ arr[j-14] ^ arr[j-16],1);
    		}
    		int a=H0,b=H1,c=H2,d=H3,e=H4,T=0;
        	for(int x=0;x<=19;x++) {
        		T = ROTL(a,5)+((b&c)|((~b)&d))+e+arr[x]+K1;
        		e=d;
        		d=c;
        		c=ROTL(b,30);
        		b=a;
        		a=T;
        	}
        	for(int x=20;x<=39;x++) {
        		T = ROTL(a,5)+(b^c^d)+e+arr[x]+K2;
        		e=d;
        		d=c;
        		c=ROTL(b,30);
        		b=a;
        		a=T;
        	}
        	for(int x=40;x<=59;x++) {
        		T = ROTL(a,5)+((b&c)|(b&d)|(c&d))+e+arr[x]+K3;
        		e=d;
        		d=c;
        		c=ROTL(b,30);
        		b=a;
        		a=T;
        	}
        	for(int x=60;x<=79;x++) {
        		T = ROTL(a,5)+(b^c^d)+e+arr[x]+K4;
        		e=d;
        		d=c;
        		c=ROTL(b,30);
        		b=a;
        		a=T;
        	}
        	H0+=a;
        	H1+=b;
        	H2+=c;
        	H3+=d;
        	H4+=e;
    	}
    	String H0len = Integer.toHexString(H0);
    	String H1len = Integer.toHexString(H1);
    	String H2len = Integer.toHexString(H2);
    	String H3len = Integer.toHexString(H3);
    	String H4len = Integer.toHexString(H4);
    	if(H0len.length()<8) {
    		StringBuilder sbH0 = new StringBuilder(H0len);
    		sbH0.insert(0, 0);
    		H0len = sbH0.toString();
    	}else if(H1len.length()<8) {
    		StringBuilder sbH1 = new StringBuilder(H1len);
    		sbH1.insert(0, 0);
    		H1len = sbH1.toString();
    	}else if(H2len.length()<8) {
    		StringBuilder sbH2= new StringBuilder(H2len);
    		sbH2.insert(0, 0);
    		H2len = sbH2.toString();
    	}else if(H3len.length()<8) {
    		StringBuilder sbH3 = new StringBuilder(H3len);
    		sbH3.insert(0, 0);
    		H3len = sbH3.toString();
    	}else if(H4len.length()<8) {
    		StringBuilder sbH4 = new StringBuilder(H4len);
    		sbH4.insert(0, 0);
    		H4len = sbH4.toString();
    	}
    	
		//String messageHash = H0len.toHexString;
    	String messageHash = H0len+H1len+H2len+H3len+H4len;
		String res1 = "";
     	for(int i=0;i<bits;i++){
			res1 = res1+messageHash.charAt(i);
		    //System.out.println(res1);
     	}
		return res1;
    	
    }
   
}
