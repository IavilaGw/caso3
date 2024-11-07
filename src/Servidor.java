import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Scanner;
import java.util.Map;
import java.util.HashMap;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.io.FileOutputStream;

public class Servidor {

    private static final int SERVER_PORT = 3400;
    private KeyPair rsaKeyPair;
    private Map<String, String> packageStatusTable;

    public Servidor() throws Exception {
        packageStatusTable = new HashMap<>();
        initPackageStatusTable();
        generateAndSaveKeys();
    }

    private void initPackageStatusTable() {
        packageStatusTable.put("001", "ENOFICINA");
        packageStatusTable.put("002", "RECOGIDO");
        packageStatusTable.put("003", "ENENTREGA");
        packageStatusTable.put("004", "ENCLASIFICADO");
        packageStatusTable.put("005", "DESPACHADO");
        packageStatusTable.put("006", "ENTREGADO");
        packageStatusTable.put("007", "DESCONOCIDO");
    }

    private void generateAndSaveKeys() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024);
        rsaKeyPair = keyPairGen.generateKeyPair();

        try (FileOutputStream fos = new FileOutputStream("publicKey.key")) {
            fos.write(rsaKeyPair.getPublic().getEncoded());
        }

        try (FileOutputStream fos = new FileOutputStream("privateKey.key")) {
            fos.write(rsaKeyPair.getPrivate().getEncoded());
        }

        System.out.println("Llaves RSA generadas y guardadas en archivos.");
    }

    public void start(int numDelegados) throws Exception {
        ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
        ExecutorService pool = Executors.newFixedThreadPool(numDelegados);
        System.out.println("Servidor iniciado en el puerto " + SERVER_PORT);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Cliente conectado: " + clientSocket.getInetAddress());
            pool.execute(new ClientHandler(clientSocket, rsaKeyPair, packageStatusTable)); 
        }
    }

    public static void main(String[] args) {
        try {
            Servidor servidor = new Servidor();
            Scanner scanner = new Scanner(System.in);

            while (true) {
                System.out.println("Menú del Servidor:");
                System.out.println("1. Generar llaves RSA y guardarlas en archivos");
                System.out.println("2. Iniciar servidor (prueba escenario 1)");
                System.out.println("3. Prueba escenario 2");
                System.out.print("Seleccione una opción: ");

                int opcion = scanner.nextInt();

                if (opcion == 1) {
                    servidor.generateAndSaveKeys();
                } else if (opcion == 2) {
                    servidor.start(1);
                } else if (opcion == 3) {
                    System.out.println("Seleccione el número de delegados para el servidor (4, 8, o 32): ");
                    int numDelegados = scanner.nextInt();
                    scanner.close();
                    servidor.start(numDelegados);
                } else {
                    System.out.println("Opción inválida. Por favor, seleccione nuevamente.");
                }
            }
            

            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
