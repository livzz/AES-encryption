import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.print.DocFlavor.URL;

public class driver {
	public static void main(String []text)
	{
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		String key = null;
		String plainText = null;
			try {
				key = in.readLine();
				plainText = in.readLine();	
				in.close();
			} catch (IOException e) {
				
				e.printStackTrace();
			}
		new aescipher(key,plainText);
		//java.net.URL location = driver.class.getProtectionDomain().getCodeSource().getLocation();
		//System.out.println(location);
	}

}
