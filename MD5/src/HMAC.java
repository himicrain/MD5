
public class HMAC {
	
	
	MD5 md5 = new MD5();
	

	
	/*
	byte[] str2Hex(String str){
		byte[] temp = new byte[str.length()];
		
		return temp;
		
	}*/
	
	
	//异或操作
	public byte[] XOR(byte[] str, byte pad){
		byte[] finalByte = new byte[64];
		for(int i=0;i<64;i++){
			finalByte[i] = (byte) (str[i]^pad);
		}
		return finalByte;
	}
	
	//16进制转字符串
	String Hex2Str(byte[] hex){
		String finalHex2Str = "";  
        for (int i = 0; i < 16; i++) {  
              finalHex2Str += md5.b2Hex(hex[i]);  
        } 
		return finalHex2Str;
	}
	
	//主算法
	String getHMACStr(String data, String key){
		//key byte
		byte[] tempKey = new byte[64];
		//如果key 长度大于64
		if(key.length() > 64){
			byte[] temp = md5.MD5Bytes(key.getBytes());
			for(int i=0;i<temp.length;i++){
				tempKey[i] = temp[i];
			}
			for(int i=temp.length;i<64;i++){
				tempKey[i] = 0x00;
			}
		}else{
			for(int i=0;i<key.length();i++){
				tempKey[i] = (byte)key.charAt(i);
			}
			for(int i=key.length();i<64;i++){
				tempKey[i] = 0x00;
			}
		}
		
		//first time
		
		byte[] iStr = XOR(tempKey,(byte)0x36);
		byte[] iByte = new byte[iStr.length+data.length()];
		for(int i=0;i<iStr.length;i++){
			iByte[i] = iStr[i];
		}
		for(int i=iStr.length;i<iByte.length;i++){
			iByte[i] = (byte) data.charAt(i-iStr.length);
		}
		iStr = md5.MD5Bytes(iByte);
		

		
		//second times
		byte[] oStr = XOR(tempKey,(byte)0x5c);
		byte[] oBytes = new byte[oStr.length+iStr.length];
		for(int i=0;i<oStr.length;i++){
			oBytes[i] = oStr[i];
		}
		for(int i=oStr.length;i<oBytes.length;i++){
			oBytes[i] = iStr[i-oStr.length];
		}
		oStr = md5.MD5Bytes(oBytes);
		
		
		return Hex2Str(oStr);
	}
	
	public String Hex2HexStr(byte[] hex){
		String temp = "";
		
		for(int i=0;i<hex.length;i++){
			temp += (char)hex[i];
		}
		
		return temp;
	}
	
	public static void main(String[] args) {

		HMAC hmac = new HMAC();
		//这些测试都是文档里给的
		//test 1
		String data = "what do ya want for nothing?";
		String key = "Jefe";
		
		System.out.println("Key is : \"" + key+"\"");
		System.out.println("the data is : \"" + data+"\"");
		System.out.println("the H-MAC value is : " + hmac.getHMACStr(data, key));
		System.out.println("\n");
		
		//test 2
		byte[] keyByte = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
		key = hmac.Hex2HexStr(keyByte);
		data = "Hi There";
		System.out.println("Key is : 0x" + hmac.Hex2Str(keyByte));
		System.out.println("the data is : \"" + data+"\"");
		System.out.println("the H-MAC value is : " + hmac.getHMACStr(data, key));
		
		System.out.println("\n");
		
		//test 2
		byte[] keyByte1 = {0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c};
		key = hmac.Hex2HexStr(keyByte1);
		data = "Test With Truncation";
		System.out.println("Key is : 0x" + hmac.Hex2Str(keyByte1));
		System.out.println("the data is : \"" + data+"\"");
		System.out.println("the H-MAC value is : " + hmac.getHMACStr(data, key));

	}

}
