/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;

public class web_server {
    
    
    ///
    
    

    ServerSocket sersock;// = new ServerSocket(3000);

    Socket sock;// = sersock.accept();
    BufferedReader keyRead;// = new BufferedReader(new InputStreamReader(System.in));
    OutputStream ostream;// = sock.getOutputStream();
    PrintWriter pwrite;// = new PrintWriter(ostream, true);
    InputStream istream;// = sock.getInputStream();
    BufferedReader receiveRead;// = new BufferedReader(new InputStreamReader(istream));
    String receiveMessage, sendMessage;
    String pass;
    String cb_sessionkey;
    BigInteger d, n;
    String bws_sessionkey;
    String cws_sessionkey;
    String shared_sesionkey;
    String product;

    public void send_message(PrintWriter pwrite_in, String msg) {
        pwrite_in.println(msg);
        pwrite_in.flush();
    }

    public String readProductlist(String sCurrentLine, String Amount) {
        String amount1 = Amount.substring(0, 2);

        int aInt = Integer.parseInt(amount1);

        String[] tokens = sCurrentLine.split(",");
        System.out.println("Product,Price(in $)");
        for (int i = 0; i < tokens.length; i++) {
            if (i % 2 != 0) {
                System.out.println(tokens[i]);
                if (tokens[i].equals(amount1)) {
                    return tokens[i - 1];
                }
            } else {
                System.out.print(tokens[i] + ",");

            }
            // System.out.println(tokens[i]);
        }
        return null;
    }

    public void find_product(String msg) throws Exception {
        String product_list = readProducts("../amazon/product_list.txt");

        System.out.println(product_list);
        System.out.println(msg);
        this.product = readProductlist(product_list, msg);
        System.out.println(this.product);
    }

    public void init_open() {
        try {
            this.sersock = new ServerSocket(3002);
            System.out.println("Amazon ready!!!");
            this.sock = sersock.accept();
            this.keyRead = new BufferedReader(new InputStreamReader(System.in));
            this.ostream = sock.getOutputStream();
            this.pwrite = new PrintWriter(ostream, true);
            this.istream = sock.getInputStream();
            this.receiveRead = new BufferedReader(new InputStreamReader(istream));

        } catch (Exception e) {
            System.out.println("Error running web-server:");
        }
    }

    public void getPrivateKey() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader("../amazon/pri_key.txt"));
        String sCurrentLine;
        sCurrentLine = br.readLine();
        String delims = ","; // so the delimiters are:  + - * / ^ space
        String[] tokens = sCurrentLine.split(delims);

        String decryption_key = tokens[0];
        String num = tokens[1];

        this.d = new BigInteger(decryption_key);
        this.n = new BigInteger(num);
    }

    public String readProducts(String path) throws Exception {
        //String name = "Bob";
        BufferedReader br = new BufferedReader(new FileReader(path));
        String line = "";
        String sCurrentLine;
        StringBuffer sb = new StringBuffer();
        while ((sCurrentLine = br.readLine()) != null) {
				//System.out.println(sCurrentLine);

            sb.append(sCurrentLine);
            sb.append(",");
                                   // System.out.println(tokens[i]);

            //return line;
        }
        line = sb.toString();
        return line;
    }

    public static void main(String[] args) throws Exception {
        
        web_server ws = new web_server();

        
        //Open Sever Socket
        ws.init_open();

        if (true) {

            //Establish Session Key
            encrypt_decrypt myEncryptor_bws = new encrypt_decrypt("RANDOM_KEY_NAME");
            String encrypted = "";
             String line1 = null;
            StringBuffer stringBuffer1 = new StringBuffer();
             try {
                int count = 0;
                while (count < 2) {
                    //encrypt_decrypt myEncryptor = new encrypt_decrypt(s.cb_sessionkey);
                    line1 = ws.receiveRead.readLine();
                    stringBuffer1.append(line1).append("\n");
                    count++;
                }
            } catch (Exception e) {
                System.out.println(e);
            }
             ws.receiveMessage = stringBuffer1.toString();
         
                System.out.println(ws.receiveMessage);
                ws.getPrivateKey();
                ws.shared_sesionkey = "amazon9843";
                encrypt_decrypt myEncryptor_long_bws = new encrypt_decrypt(ws.shared_sesionkey);
                String message = myEncryptor_long_bws.decrypt(ws.receiveMessage);
                // Extract Session key by decrypting with private key
               // String message = new String((new BigInteger(ws.receiveMessage)).modPow(ws.d, ws.n).toByteArray());
                String tokens[] = message.split(",");
                ws.bws_sessionkey = tokens[0];
                String nonce = tokens[1];
                System.out.println("Session key to Broker is: " + ws.bws_sessionkey);

                // Send Nonce to Broker encrypted with session key
                myEncryptor_bws = new encrypt_decrypt(ws.bws_sessionkey);
                encrypted = myEncryptor_bws.encrypt(nonce);
                ws.send_message(ws.pwrite, encrypted);
            // Receive msg from broker
            String line = null;
            StringBuffer stringBuffer = new StringBuffer();
            try {
                int count = 0;
                while (count < 6) {
                    //encrypt_decrypt myEncryptor = new encrypt_decrypt(s.cb_sessionkey);
                    line = ws.receiveRead.readLine();

                    stringBuffer.append(line).append("\n");
                    count++;
                }
            } catch (Exception e) {
                System.out.println(e);
            }
            ws.receiveMessage = stringBuffer.toString();
            System.out.println(ws.receiveMessage);
            String decrypted = myEncryptor_bws.decrypt(ws.receiveMessage);
            ws.cws_sessionkey = new String((new BigInteger(decrypted)).modPow(ws.d, ws.n).toByteArray());
            System.out.println("Session Key to Client is : " + ws.cws_sessionkey);

            //Send Product list to client over sessioon key
            String product_list = ws.readProducts("../amazon/product_list.txt");
            encrypt_decrypt myEncryptor_cws = new encrypt_decrypt(ws.cws_sessionkey);
            String encrypted1 = myEncryptor_cws.encrypt(product_list);
            String encrypted2 = myEncryptor_bws.encrypt(encrypted1);
            System.out.println(encrypted2);
            ws.send_message(ws.pwrite, encrypted2);

            // Payment Confirmation
            int amount_flag = 0;
            while (amount_flag == 0) {
                if ((ws.receiveMessage = ws.receiveRead.readLine()) != null) {
                    decrypted = myEncryptor_bws.decrypt(ws.receiveMessage);
                    System.out.println(decrypted);

                    ws.find_product(decrypted);
                    if (ws.product == null) {
                        encrypted = myEncryptor_bws.encrypt("No");
                        System.out.println("No");
                        ws.send_message(ws.pwrite, encrypted);
                        amount_flag = 0;
                        continue;
                    }
                    // ws.find_product(decrypted);
                    encrypted = myEncryptor_bws.encrypt("Yes it is!!!");
                    ws.send_message(ws.pwrite, encrypted);
                    amount_flag = 1;
                }
            }
            // Amount Received
            if ((ws.receiveMessage = ws.receiveRead.readLine()) != null) {
                decrypted = myEncryptor_bws.decrypt(ws.receiveMessage);
                System.out.println(decrypted);

                // Send the Product to Client :)
                encrypted1 = myEncryptor_cws.encrypt(ws.product);
                encrypted2 = myEncryptor_bws.encrypt(encrypted1);
                ws.send_message(ws.pwrite, encrypted2);

                
                 ServerSocket servsock = null;
        Socket sock = null;
        
        servsock = new ServerSocket(33334);
                    if (true) {
                System.out.println("Waiting...");
                try {
                    sock = servsock.accept();
                    System.out.println("Accepted connection : " + sock);
                    // send file
                    File f = new File("../amazon/" +ws.product);
                    FileInputStream File_In_Stream = new FileInputStream(f);
                        OutputStream oos 	= sock.getOutputStream();	
                        DataOutputStream Data_Stream_Out 	= new DataOutputStream( (oos));
				Data_Stream_Out.writeLong(f.length());

				//write file to Data_Stream_Out
                              
                                int n = 0;
			byte[]buf = new byte[1024];
                        byte[]encrypted_product = new byte[1024];
                        int i=0;
                        //System.out.println("Encrypted Server Side");
                        //encrypt_decrypt myEncryptor_cws= new encrypt_decrypt(ws.cws_sessionkey);
                        
                        System.out.println("Writing to File");
                        encrypt_decrypt myEncryptor= new encrypt_decrypt(ws.cws_sessionkey);
				while((n = File_In_Stream.read(buf)) != -1)
				{
                                    
                                   // System.out.println(encrypted.length);
                                    String text = new String(buf);
                                    byte[] buf1 = text.getBytes();
                                    
                                     encrypted_product=myEncryptor.encryptBytes(buf);
                                    
                                     Data_Stream_Out.write(encrypted_product,0,encrypted_product.length);
					Data_Stream_Out.flush();
                                        
                                        
				}
				//File_In_Stream.close();

                    System.out.println("Done.");
                }
                catch(Exception s)
                {
                    System.out.println(s);
                }
                    }
                
            }

        }

    }

}
