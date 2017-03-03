import java.math.BigInteger;

/**
 * 
 */

/**
 * @author 
 *
 */
public class aescipher {

	/**
	 * @param args
	 */
		public static int round;
		public static byte[][] roundKey = new byte[44][4];
		public static String[] keyHexString;
		public static byte[] state; 
		// ////////////////////////////////////////////////////////////////////////////////////
		// Precomputed tables.
		// ////////////////////////////////////////////////////////////////////////////////////
		// Precomputed Rijndael S-BOX
		private static final char sbox[] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
				0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72,
				0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04,
				0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c,
				0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20,
				0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33,
				0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
				0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e,
				0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde,
				0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4,
				0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba,
				0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5,
				0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69,
				0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
				0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
		//Precomputed Round Constant
		private static final char rcon[] = {
				0x8D,0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
		};
		// Multiplication function over GF(2^8) used in the MixColumns pass
		public static byte GFMult(byte a, byte b) {
			byte r = 0, t;
			while (a != 0) {
				if ((a & 1) != 0)
					r = (byte) (r ^ b);
				t = (byte) (b & 0x80);
				b = (byte) (b << 1);
				if (t != 0)
					b = (byte) (b ^ 0x1B);
				a = (byte) ((a & 0xFF) >> 1);
			}
			return r;
		}
		// AES MixColums and InvMixColumns passes
		private static byte[][] MixColumns(byte[][] state) {
			int[] tmp = new int[4];
			// In this way I can use a single method to do both the inverted and the
			// straight version. I choose the correct first operand of the
			// multiplication by checking the boolean "inverted" flag.
			byte a = (byte) (0x03);
			byte b = (byte) (0x01);
			byte c = (byte) (0x01);
			byte d = (byte) (0x02);
	 
			for (int i = 0; i < 4; i++) {
				tmp[0] = GFMult(d, state[0][i]) ^ GFMult(a, state[1][i]) ^ GFMult(b, state[2][i]) ^ GFMult(c, state[3][i]);
				tmp[1] = GFMult(c, state[0][i]) ^ GFMult(d, state[1][i]) ^ GFMult(a, state[2][i]) ^ GFMult(b, state[3][i]);
				tmp[2] = GFMult(b, state[0][i]) ^ GFMult(c, state[1][i]) ^ GFMult(d, state[2][i]) ^ GFMult(a, state[3][i]);
				tmp[3] = GFMult(a, state[0][i]) ^ GFMult(b, state[1][i]) ^ GFMult(c, state[2][i]) ^ GFMult(d, state[3][i]);
				for (int j = 0; j < 4; j++)
					state[j][i] = (byte) (tmp[j]);
			}
	 
			return state;
		}
		public static byte getRcon(int round)
		{
			
			return (byte)rcon[round & 0xFF];
		}
		/**
		* doXOR method is used for XORing for creating round keys
		*
		*
		*
		*
		*
		*
		*/
		public byte[] doXor(byte[]a, byte[]b)
		{
			byte[] temp = new byte[4];
			for(int i=0;i<4;i++)
			{
				temp[i] = (byte) (a[i]^ b[i]);
			}
			return temp;
		}
		/*
		* aesStateXOR method finds the XOR or the state and round key
		*
		*@param a: byte array of the State
 		*		b: byte array of the round key
		*
		*
		*@return byte[][]: byte array of the new state
		**/
		public  byte[][] aesStateXOR(byte[][]a, byte[][]b)
		{
			byte[][] temp = new byte[4][4];
			for(int i=0;i<4;i++)
			{
				for(int j = 0;j<4;j++)
				{
					temp[j][i] = (byte) (a[j][i]^ b[j][i]);
				}
			}
			return temp;
		}
		//Byte Shifting of creating round Key 		
		public byte[] shifting(byte[][] a,int row)
		{
			byte [] b = new byte[4];
			b[3] = a[row][0];
			
			for(int i=0;i<3;i++)
			{
				b[i] = a[row][i+1];
			} 
			return b;
		}
		
		// AES ShiftRow and InvShiftRow passes
		private byte[][] ShiftRows(byte[][] state) {
			byte[] t = new byte[4];
			for (int i = 1; i < 4; i++) {
				for (int j = 0; j < 4; j++)
					t[j] = state[i][(j + i) % 4];
				for (int j = 0; j < 4; j++)
					state[i][j] = t[j];
			}
			return state;
		}
		
		// Converts a string to the equivalent hex representation
		public static String stringToHexString(String string) {
			return String.format("%x", new BigInteger(1, string.getBytes()));
		}
		// AES SubBytes and InvSubBytes passes
		static byte[][] SubBytes(byte[][] state) {
			// Select the correct s-box, either inverted or not.
			char[] _sbox =  sbox;
			for (int i = 0; i < 4; i++)
				for (int j = 0; j < 4; j++)
					state[i][j] = (byte) _sbox[state[i][j] & 0xFF];
			// The mask is used to shift the byte value to the unsigned (positive)
			// one
			return state;
		}
		
		static byte[][] SubBytesForKey(byte[][] state) {
			// Select the correct s-box, either inverted or not.
			char[] _sbox =  sbox;
			for (int i = 0; i < 2; i++)
				for (int j = 0; j < 2; j++)
					state[i][j] = (byte) _sbox[state[i][j] & 0xFF];
			// The mask is used to shift the byte value to the unsigned (positive)
			// one
			return state;
		}
		
		// Converts the given string containing an hex representation to the
		// corresponding byte array
		public byte[] hexStringToByteArray(String hexString) {
			int len = hexString.length();
			byte[] data = new byte[len / 2];
			for (int i = 0; i < len; i += 2) {
				data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(
						hexString.charAt(i + 1), 16));
			}
			return data;
		}
	 
		// Converts the given byte array to the corresponding textual form
		public String byteArrayToHexString(byte[] hexArray) {
			String hexString = new String();
			for (byte hex : hexArray)
			{
				if((Integer.parseInt( Integer.toString(hex & 0xFF, 16),16 ) )<16 )
				{
					hexString +="0";
				}
				hexString += Integer.toString(hex & 0xFF, 16).toUpperCase();
			}
			return hexString;
		}
		
		// Converts the given byte array to a 4 by 4 matrix by column
		private byte[][] arrayToMatrix(byte[] array) {
			byte[][] matrix = new byte[4][4];
			for (int i = 0; i < 4; i++)
				for (int j = 0; j < 4; j++)
					matrix[i][j] = array[i * 4 + j];
			return matrix;
		}
		
		private byte[][] arrayToMatrix2(byte[] array) {
			byte[][] matrix = new byte[2][2];
			for (int i = 0; i < 2; i++)
				for (int j = 0; j < 2; j++)
					matrix[j][i] = array[i * 2 + j];
			return matrix;
		}
	 
		// Converts the given matrix to the corresponding array (by columns)
		private byte[] matrixToArray(byte[][] matrix) {
			byte[] array = new byte[16];
			for (int i = 0; i < 4; i++)
				for (int j = 0; j < 4; j++)
					array[i * 4 + j] = matrix[j][i];
			return array;
		}
		
		private byte[] matrixToArray2(byte[][] matrix) {
			byte[] array = new byte[4];
			for (int i = 0; i < 2; i++)
				for (int j = 0; j < 2; j++)
					array[i * 2 + j] = matrix[j][i];
			return array;
		}
		
		public String[][] stringMatrix(String s)
		{
			 
			String [][] rr = new String[4][4];
			
			 int x = 0;
				for(int col = 0; col<4;col++)
				{
					for(int row = 0; row<4; row ++)
					{
						rr[col][row] = "";
						for(int k = 0; k<2;k++)
						{
							rr[col][row]=rr[col][row]+s.substring(x,x+1);
							x++;
						}
					}
			}
			return rr;
		}
		
		/**
		*getRow gets the row needed from the round key
		* 
		*@param row: the row required
		*
		*
		*
		*@return byte[]: Byte array of the key needed
		*/
		public byte[] getRow(int row)
		{
			byte[] temp = new byte[4];
			for(int i = 0;i<4;i++)
			{
				temp[i] = roundKey[row][i];
			}
			return temp;
		}
		/**
		*fillState creates the state matrix
		*
		*@param byte[]: Takes the byte array of the state
		*
		*
		*
		*@returns byte[][]: The matrix form of the state		
		*/
		public static byte[][] fillState(byte[] s)
		{
			byte[][] temp = new byte[4][4];
			for(int i = 0;i<4;i++)
			{
				for(int j = 0;j<4;j++)
				{
					temp[j][i] = s[i*4 + j];
				}
			}
			return temp;
		}
		/**
		* getKey extracts the key from the roundKey array the is required for a round
		*
		*@param round: the current round being executed 
		*
		*
		*@return byte[][]: returns the round key in byte[][]
		*/
		public static byte[][] getKey(int round)
		{
			byte[][] temp = new byte[4][4]; 
			for(int i = round*4,count=0;count<4;i++,count++)
			{
				for(int j = 0;j<4;j++)
				{
					temp[j][count] = roundKey[i][j];
				}
			}
			return temp;
		}
		/**
		* AEScipher is a constructor that generates the round key and use those key to 
		*			encrypt the given data
		*
		*@param ss: It is the Key that will be used for Round Key Generation
		*
		*		file: It is the painText that is to be encrypted
		* 
		*/
	aescipher(String key,String plainText) {
		
		// TODO Auto-generated method stub
		 
		//String file = "54776F204F6E65204E696E652054776F";
		int row = 4;
		byte[] temp = new byte[4];
		//ss = stringToHexString(ss);
		byte byteKey[] = hexStringToByteArray(key);
		byte keyMatrix[][] = arrayToMatrix(byteKey);
		for(int i = 0;i<4;i++)
		{
			for(int j = 0;j<4;j++)
			{
				//System.out.print(mat[i][j]+" ");
				roundKey[i][j] = keyMatrix[i][j];
			}
			//System.out.print("\n");
		}
		//System.out.println(ss);
		for(int round = 1 ;round<11;round++)
		{
			//System.out.println("++++++++++++++++++++++++");
			for(int count = 0;count<4;count++,row++)
			{
				if(row%4==0)
				{
					temp = shifting(roundKey,row-1);
					temp = matrixToArray2(SubBytesForKey(arrayToMatrix2(temp)));
					byte[] rcon = {0,0,0,0};
					rcon[0] = getRcon(round);
					temp = doXor(getRow(row-4),doXor(temp,rcon));
				}
				else
				{
					temp = doXor(getRow(row-4),getRow(row-1));	
				}
				//System.out.println(byteArrayToHexString(temp));
				roundKey[row] = temp;
			}
			//System.out.println("++++++++++++++++++++++++");
		}	
		
//		for(int i = 0;i<11;i++)
//		{
//			System.out.println(byteArrayToHexString(matrixToArray(getKey(i))));
//		}
		byte[][] textMatrix = fillState(hexStringToByteArray(plainText));
		//System.out.println("Round "+0+"--->"+byteArrayToHexString(matrixToArray(textMatrix)));
		textMatrix = aesStateXOR(textMatrix, getKey(0));
		for(int i =1;i<11;i++)
		{
			textMatrix = SubBytes(textMatrix);
			textMatrix = ShiftRows(textMatrix);
			if(i<10)
			textMatrix = MixColumns(textMatrix);
			textMatrix = aesStateXOR(textMatrix, getKey(i));
			//System.out.println("Round "+i+"--->"+byteArrayToHexString(matrixToArray(textMatrix)));
		}
		System.out.println(byteArrayToHexString(matrixToArray(textMatrix)));
	}
}
