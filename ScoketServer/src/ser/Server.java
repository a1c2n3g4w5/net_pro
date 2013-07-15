package ser;


import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Hashtable;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import rsa.RSA;


public class Server extends JFrame{
	RSA serrsa=new RSA();
	RSA clirsa=new RSA();
	
	Hashtable<String, BigInteger> pkey=null;
	private static final long serialVersionUID = 3137448640400633755L;
	int flag=1;
	private JPanel jPanel=new JPanel();
	ObjectOutputStream oos=null;
	ObjectInputStream ois=null;
//	InputStream is=null;
//	OutputStream  os=null;
	
	private JTextArea jTextArea=new JTextArea();
	private JTextField jTextField=new JTextField();
	private JButton jButton=new JButton("开启服务器");
	private JButton jButton2=new JButton("发送");
	public Server() {
		
		jPanel.setLayout(null);
		
		jTextArea.setBounds(20, 20, 400, 180);
		jTextArea.setEditable(false);
		jPanel.add(jTextArea);
		
		jTextField.setBounds(20,210,300,30);
		jPanel.add(jTextField);
		
		jButton2.setBounds(350, 200, 80, 40);
		jPanel.add(jButton2);
		jButton2.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				new Thread(new SendThread()).start();
			}
		});
		
			
		jButton.setBounds(420, 20, 150, 50);
		jPanel.add(jButton);
		jButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				new Thread(new ClientThread()).start();
				
			}
		});
		
		this.add(jPanel);
		this.setBounds(100, 150, 600, 400);
		this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		this.setTitle("服务器端");
		this.setResizable(false);
		this.setVisible(true);
	}
	
	public static void main(String argv[]){
		new Server();
	}
	public class SendThread implements  Runnable{
		@Override
		public void run() {
			sendMsg();
		}

	}
	
	public void sendMsg() {
		System.out.println("服务器---开始发送信息");
		String msg="hello";
		msg=jTextField.getText();
		jTextField.setText("");
		try {
			jTextArea.append("\n"+"服务器："+msg);
			System.out.println("服务器端---发出消息   "+msg);
			msg=URLEncoder.encode(msg,"gbk");
			msg=new String( clirsa.pubEncrypt(msg.getBytes()) , "ISO-8859-1");
			oos.writeObject(msg);
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public class RecThread implements  Runnable{
		@Override
		public void run() {
			recMsg();
		}

	}
	@SuppressWarnings("unchecked")
	private void recMsg() {
		int flag=1;
		System.out.println("服务器---开始接收信息");
		String string="hello";
		try {
			try {
				pkey=(Hashtable<String, BigInteger>)ois.readObject();
				clirsa.setPublicKey(pkey);
				
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
			while(flag==1){
				try {
					string=(String)ois.readObject();
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				}
				string=new String(serrsa.priDecrypt(string.getBytes("ISO-8859-1")));
		        string=URLDecoder.decode(string,"gbk");
		        jTextArea.append("\n"+"客户端："+string);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	
	public class ClientThread implements Runnable{
		ServerSocket sc;
		Socket s;
		
	
		@Override
		public void run() {
			System.out.println("run");
			try {
				sc = new ServerSocket(8888);
				s=sc.accept();
				serrsa.genKey(4096);//产生client公钥
				clirsa.genKey(4096);
				pkey=serrsa.getPublicKey();
				
				ois=new ObjectInputStream(s.getInputStream());
				oos=new ObjectOutputStream(s.getOutputStream());
				
				oos.writeObject(pkey);
				oos.flush();
				
				
//		        is=s.getInputStream();;
//		        os=s.getOutputStream();
		        new Thread(new RecThread()).start(); 
		      
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		
	}

	
}
