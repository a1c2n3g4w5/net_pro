package frame;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.Hashtable;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import rsa.RSA;


public class MainFrame extends JFrame{
	
	private static final long serialVersionUID = -1895032579874976498L;
	Hashtable<String, BigInteger> pkey=null;
	RSA serrsa=new RSA();
	RSA clirsa=new RSA();
	
	
	Socket s=null;
	private int flag=1;
	ObjectOutputStream oos=null;
	ObjectInputStream ois=null;
//	InputStream is=null;
//	OutputStream  os=null;
	
	private JPanel jPanel=new JPanel();
	private JTextArea jTextArea=new JTextArea();
	private JTextField jTextField=new JTextField();
	private JButton jButton=new JButton("����");
	public MainFrame()  {
		// TODO Auto-generated constructor stub
		jPanel.setLayout(null);
		//���ӷ�����
		new Thread(new SocThread()).start();
		
        
		
		jTextArea.setBounds(20, 20, 400, 180);
		jTextArea.setEditable(false);
		jPanel.add(jTextArea);
		
		jTextField.setBounds(20,210,300,30);
		jPanel.add(jTextField);

		jButton.setBounds(350, 200, 80, 40);
		jButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				new Thread(new SendThread()).start();
			}
		});
		jPanel.add(jButton);
		
	
		
		this.add(jPanel);
		this.setBounds(700, 150, 450, 400);
		this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		this.setTitle("�ͻ���");
		this.setResizable(false);
		this.setVisible(true);
	}
	
	public static void main(String argv[]) {
		new MainFrame();
	}
	public class RecThread implements  Runnable{
		@Override
		public void run() {
			recMsg();
		}

	}
	public class SocThread implements  Runnable{
		@Override
		public void run() {
			System.out.println("�ͻ���-----���������߳�");
			SocConn();
		}

	}
	public class SendThread implements  Runnable{
		@Override
		public void run() {
			sendMsg();
		}

	}
	//���ӷ�����
	private void SocConn() {
		
		try {
			s=new Socket("localhost",8888);
			clirsa.genKey(4096);//������Կ
			serrsa.genKey(4096);
			 pkey = clirsa.getPublicKey();
			
			oos=new ObjectOutputStream(s.getOutputStream());
			ois=new ObjectInputStream(s.getInputStream());
			oos.writeObject(pkey);
			oos.flush();
//	        is=s.getInputStream();
//	        os=s.getOutputStream();
	      //������Ϣ
	        new Thread(new RecThread()).start();
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public void sendMsg() {
		System.out.println("�ͻ���-----��ʼ������Ϣ");
		String msg="hello";
		msg=jTextField.getText();
		jTextField.setText("");
		try {
			//�������˹�Կ����
			jTextArea.append("\n"+"�ͻ��ˣ�"+msg);
			System.out.println("�ͻ���---������Ϣ   "+msg);
			msg=URLEncoder.encode(msg,"gbk");
			msg=new String( serrsa.pubEncrypt(msg.getBytes()) , "ISO-8859-1");
			oos.writeObject(msg);
	
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	//������Ϣ
	@SuppressWarnings("unchecked")
	private void recMsg() {
		System.out.println("�ͻ���-----��ʼ������Ϣ");
		//��ȡ��Կ
		
		String string="hello_msg";
		
		try {
			try {
				pkey=(Hashtable<String, BigInteger>)ois.readObject();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}
			serrsa.setPublicKey(pkey);//���÷�������Կ
			System.out.println(serrsa.getPublicKey().get("b"));
			while(flag==1){
				 try {
					string=(String)ois.readObject();
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				}
					string=new String(clirsa.priDecrypt(string.getBytes("ISO-8859-1")));
			        string=URLDecoder.decode(string,"gbk");
			        
				jTextArea.append("\n"+"��������"+string);
			}	
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
