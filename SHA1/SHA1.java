package crpyto;
public class SHA1 {

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

	public static int ROTL(int x,int bit) {
		return ((x<<bit) | (x>>>(128-bit)));
	}
    
    public static void main(String[] args){
        String message = "";
		System.out.println();
        String[] inputs = {"This is a test of SHA-1.","Kerckhoff\'s principle is the foundation on which modern cryptography is built.","SHA-1 is no longer considered a secure hashing algorithm","SHA-2 or SHA-3 should be used in place of SHA-1.","Never roll your own crypto!"};
          for(int i=0;i<inputs.length;i++){
           message = inputs[i];
            K1 = 0X5A827999;
            K2 = 0X6ED9EBA1;
            K3 = 0X8F1BBCDC;
            K4 = 0XCA62C1D6;
            H0 = 0X67452301;
            H1 = 0XEFCDAB89;
            H2 = 0X98BADCFE;
            H3 = 0X10325476;
            H4 = 0XC3D2E1F0;
            
            byte[] bytes = message.getBytes(); 
            StringBuilder sb = new StringBuilder();           
            for(byte b : bytes){
                int val = b;
                for(int j=0;j<8;j++){
                    sb.append((val & 128) == 0 ? 0 : 1);
                    val <<= 1;
                }
            }
            mlen = sb.toString().length();
            padding(message,sb.toString());
		}
         
    }
    
    public static void createMessage(String message, String addOne, int zero, String len) {
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
    	hash(arr);
    }    
    
    public static void padding(String input, String message){
        int len = input.length() * 8 - 8;
        String len2 = addZeros(len+8);
        int temp = (len)%512;
        if(432-temp<0) {
        	int a = 512 - temp;
        	temp = a + 440 + temp + 64;
	    }else {
	    	temp = 432 - temp;
	    }
        int zeros = temp;
        String add = "10000000";
        message = message.replaceAll("\\s+",""); 
        createMessage(message,add,zeros,len2);
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
    
    public static String hash(int[] m) {
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
    	
    	String messageHash = H0len+H1len+H2len+H3len+H4len;
    	System.out.println(""+messageHash);
    	return null;
    }
    
    
    
}
