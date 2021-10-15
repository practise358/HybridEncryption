/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package controllers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.awt.Desktop;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.sql.PreparedStatement;
import java.sql.Connection;
import java.net.URL;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.util.Callback;
import utils.ConnectionUtil;


public class HomeController implements Initializable {
    @FXML
    private Label label;
    @FXML
    private TextArea txt_data;
    @FXML
    private TextField txt_key;
    @FXML
    private TextField txt_outfile;
    @FXML
    private TextArea txtArea_result;
    @FXML
    private Button uploadFilesBtn;
    @FXML
    private Button encryptFileBtn;
    @FXML
    private VBox pnl_scroll;
    @FXML
    private RadioButton radio_aes;
    @FXML
    private RadioButton radio_3des;
    @FXML
    private RadioButton radio_rsa;
    @FXML
    private RadioButton radio_des;
    @FXML
    private RadioButton radio_ecc;
    @FXML
    private RadioButton radio_bloFsh;

    @FXML
    private TableView tableview;
    @FXML
    private Button chooseFile;

    List<String> lstFile;
    @FXML
    private  Button btnSingleFileChooser;
    @FXML
    private Label labSingleFile;

    private static final String SALT = "ThisIsSalt";
    private static Cipher cipher;
    private final String stdName="secp256r1";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";
    private static  File file;
    PreparedStatement preparedStatement;
    Connection connection;
    private static final String key = "jackrutorial.com";





    public HomeController() {

        connection = (Connection) ConnectionUtil.conDB();
    }
    Preferences preferences;

    @Override
    public void initialize(URL url, ResourceBundle rb) {
     preferences=Preferences.userRoot();
        buildData();
        //fetRowList();
        lstFile=new ArrayList<>();
        lstFile.add("*.txt");
        lstFile.add("*.doc");
       // lstFile.add("*.DOCX");
       // lstFile.add("*.docx");

    }





    @FXML
    private void home(MouseEvent event)  {
        pnl_scroll.getChildren().clear();

        Node nodes = null;
        try {
            nodes = (Node)FXMLLoader.load(getClass().getResource("/fxml/home_menu.fxml"));
            pnl_scroll.getChildren().add(nodes);
        } catch (IOException ex) {
            Logger.getLogger(HomeController.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    @FXML
    private void uploadFiles(MouseEvent event){
        pnl_scroll.getChildren().clear();

        Node nodes = null;
        try {
            nodes = (Node)FXMLLoader.load(getClass().getResource("/fxml/upload_file.fxml"));
            pnl_scroll.getChildren().add(nodes);
        } catch (IOException ex) {
            Logger.getLogger(HomeController.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    @FXML
    private void vieDownloads(MouseEvent event){
        pnl_scroll.getChildren().clear();

        Node nodes = null;
        try {
            nodes = (Node)FXMLLoader.load(getClass().getResource("/fxml/view_files.fxml"));
            pnl_scroll.getChildren().add(nodes);
        } catch (IOException ex) {
            Logger.getLogger(HomeController.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    @FXML
    private void downloadRequests(MouseEvent event){
        pnl_scroll.getChildren().clear();

        Node nodes = null;
        try {
            nodes = (Node)FXMLLoader.load(getClass().getResource("/fxml/view_requests.fxml"));
            pnl_scroll.getChildren().add(nodes);
        } catch (IOException ex) {
            Logger.getLogger(HomeController.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    @FXML
    private void about(MouseEvent event){
        pnl_scroll.getChildren().clear();

        Node nodes = null;
        try {
            nodes = (Node)FXMLLoader.load(getClass().getResource("/fxml/about.fxml"));
            pnl_scroll.getChildren().add(nodes);
        } catch (IOException ex) {
            Logger.getLogger(HomeController.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    @FXML
    private void contact(MouseEvent event){
        pnl_scroll.getChildren().clear();

        Node nodes = null;
        try {
            nodes = (Node)FXMLLoader.load(getClass().getResource("/fxml/contact.fxml"));
            pnl_scroll.getChildren().add(nodes);
        } catch (IOException ex) {
            Logger.getLogger(HomeController.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    @FXML
    private void logout(MouseEvent event){
        pnl_scroll.getChildren().clear();

        Node nodes = null;
        try {
            nodes = (Node)FXMLLoader.load(getClass().getResource("/fxml/Item.fxml"));
            pnl_scroll.getChildren().add(nodes);
        } catch (IOException ex) {
            Logger.getLogger(HomeController.class.getName()).log(Level.SEVERE, null, ex);
        }

    }



     @FXML
    private void chooseFile(MouseEvent event ) throws IOException {
    final FileChooser fileChooser = new FileChooser();
    fileChooser.getExtensionFilters().add( new ExtensionFilter("Texts files", lstFile));
   file=fileChooser.showOpenDialog(null);
    if(file!=null){
        labSingleFile.setText(file.getName());
        preferences.put("filename", file.getName());
        labSingleFile.setTextFill(Color.web("#ff0000", 0.8));

        String content = "";
        content = new String (Files.readAllBytes(Paths.get(file.getAbsolutePath())));
       //System.out.println(Files.size(Paths.get(file.getAbsolutePath())));
        System.out.println(Files.size(file.toPath()));
        preferences.putInt("size", (int) Files.size(file.toPath()));
        txt_data.setText(content);
    }


}


    public  String AESencrypt(String secretKey, String fileInputPath, String fileOutPath) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        var key = new SecretKeySpec(secretKey.getBytes(), "AES");
        var cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        var fileInput = new File(fileInputPath);
        var inputStream = new FileInputStream(fileInput);
        var inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);

        var outputBytes = cipher.doFinal(inputBytes);

        var fileEncryptOut = new File(fileOutPath);
        var outputStream = new FileOutputStream(fileEncryptOut);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();

        System.out.println("File successfully encrypted!");
        System.out.println("New File: " + fileOutPath);
        List strings= Arrays.asList(fileEncryptOut.toString().split("/"));
        String lastindex = (String) strings.get(strings.size() - 1);
        preferences.put("outfile",lastindex);

        /* try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keyspec = new PBEKeySpec(aesSECRET_KEY.toCharArray(), SALT.getBytes(), 65536, 256);
            SecretKey sk = factory.generateSecret(keyspec);
            SecretKeySpec secretKeyspec = new SecretKeySpec(sk.getEncoded(), "AES");

            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeyspec, ivspec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            System.out.println(e);
        }
        return null;*/
        String content = "";
        content = new String (Files.readAllBytes(Paths.get(fileOutPath)));
        txtArea_result.setText(content);
        return null;

    }


    public String TDESencrypt() throws Exception {
        byte[] encryptKey = txt_key.getText().getBytes();
        DESedeKeySpec spec = new DESedeKeySpec(encryptKey);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey theKey = keyFactory.generateSecret(spec);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        IvParameterSpec IvParameters = new IvParameterSpec(new byte[]{12, 34, 56, 78, 90, 87, 65, 43});
        cipher.init(Cipher.ENCRYPT_MODE, theKey, IvParameters);
        byte[] encrypted = cipher.doFinal(txt_data.getText().getBytes(StandardCharsets.UTF_8));
        String txt = Base64.getEncoder().encodeToString(encrypted);
        txtArea_result.setText(txt);
        return null;
    }

    public  String encryptDES() throws Exception {
        byte[] encryptKey=txt_key.getText().getBytes();
        DESKeySpec spec =new DESKeySpec(encryptKey);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey key=keyFactory.generateSecret(spec);
        cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec paramSpec = new IvParameterSpec(new byte[]{ 11, 22, 33, 44, 99, 88, 77, 66});
        cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        byte[] encrypted = cipher.doFinal(txt_data.getText().getBytes(StandardCharsets.UTF_8));
        String decodeStng = Base64.getEncoder().encodeToString(encrypted);
        txtArea_result.setText(decodeStng);
        return null;
    }

    public String encryptECC() throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        ECGenParameterSpec spec = new ECGenParameterSpec(stdName);
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDH", "BC");
        gen.initialize(spec, new SecureRandom());
        KeyPair pair = gen.generateKeyPair();
        ECPublicKey partyXPubKey = (ECPublicKey) pair.getPublic();
        ECPrivateKey partyXPrivKey = (ECPrivateKey) pair.getPrivate();

        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(partyXPrivKey);
        ka.doPhase(partyXPubKey, true);
        byte[]  sharedSecret= ka.generateSecret();



// 4. Create a secret key from the session key and initialize a cipher with the secret key
        SecretKey secretKey = new SecretKeySpec(sharedSecret, 0, sharedSecret.length, "EC");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Random rand = new SecureRandom();
        byte[] bytes = new byte[16];
        rand.nextBytes(bytes);
        IvParameterSpec ivSpec = new IvParameterSpec(bytes);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] encryptMeBytes = cipher.doFinal(txt_data.getText().getBytes(StandardCharsets.UTF_8));
        String cipherString = Base64.getEncoder().encodeToString(encryptMeBytes);
        txtArea_result.setText(cipherString);
        return null;
    }

    public String encryptBlowfish(String txtToEncrypt, String key) throws Exception{
        byte[] KeyData = key.getBytes();
        SecretKeySpec KS = new SecretKeySpec(KeyData, "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(Cipher.ENCRYPT_MODE, KS);
        String encryptedtext = Base64.getEncoder().encodeToString(cipher.doFinal(txtToEncrypt.getBytes("UTF-8")));
        return encryptedtext;

    }

    public static void saveRSAKeyToFile(String fileName, BigInteger modulus, BigInteger exponent) throws IOException
    {
        ObjectOutputStream ObjOutputStream = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try
        {
            ObjOutputStream.writeObject(modulus);
            ObjOutputStream.writeObject(exponent);
        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        {
            ObjOutputStream.close();
        }
    }

    public static Key readRSAKeyFromFile(String keyFileName) throws IOException
    {
        Key key = null;
        InputStream inputStream = new FileInputStream(keyFileName);
        ObjectInputStream objectInputStream = new ObjectInputStream(new BufferedInputStream(inputStream));
        try
        {
            BigInteger modulus = (BigInteger) objectInputStream.readObject();
            BigInteger exponent = (BigInteger) objectInputStream.readObject();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            if (keyFileName.startsWith("public"))
                key = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
            else
                key = keyFactory.generatePrivate(new RSAPrivateKeySpec(modulus, exponent));

        } catch (Exception e)
        {
            e.printStackTrace();
        } finally
        {
            objectInputStream.close();
        }
        return key;
    }


    public static String encryptRSA(String plainText, String fileName) throws Exception
    {

        Key publicKey = readRSAKeyFromFile("public.key");

        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        String txt = Base64.getEncoder().encodeToString(cipherText);
        return txt;
    }



    @FXML
    private void encryptFileBtn(MouseEvent event) throws Exception {
        if (txt_key.getText().trim().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setContentText("Key cannot be empty");
            alert.setHeaderText(null);
            alert.setTitle("Encrypt");
            alert.showAndWait();
        } else if (txt_key.getText().trim().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setContentText("Key cannot be empty");
            alert.setHeaderText(null);
            alert.setTitle("Encrypt");
            alert.showAndWait();
        } else if (txt_data.getText().trim().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setContentText("Data cannot be empty");
            alert.setHeaderText(null);
            alert.setTitle("Encrypt");
            alert.showAndWait();
        }
        else if (txt_outfile.getText().trim().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setContentText("Output File Name cannot be empty");
            alert.setHeaderText(null);
            alert.setTitle("Encrypt");
            alert.showAndWait();
        }
        else {
            if (radio_aes.isSelected()) {
              AESencrypt(key, file.getAbsolutePath(),"/home/globtorch/Documents/final/HybridEncryption/JavaFX-MySQL-Login-master/src/output/" + txt_outfile.getText() +".enc");
            }

            else if (radio_3des.isSelected()) {

                if (txt_key.getText().length() <= 23) {
                    Alert alert = new Alert(Alert.AlertType.ERROR);
                    alert.setContentText("Please add your key");
                    alert.setHeaderText("Wrong key size");
                    alert.setTitle("Encrypt");
                    alert.showAndWait();
                } else {
                    TDESencrypt();
                }
            }
            else if(radio_rsa.isSelected()){
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(4096);

                // Generate the KeyPair
                KeyPair keyPair = keyPairGenerator.generateKeyPair();

                // Get the public and private key
                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();
                // Get the RSAPublicKeySpec and RSAPrivateKeySpec
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
                RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
                saveRSAKeyToFile("public.key", publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
                saveRSAKeyToFile("private.key", privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
                txtArea_result.setText(encryptRSA(txt_data.getText() , "public.key"));
            }
            else if(radio_des.isSelected()){
                encryptDES();
            }
            else if(radio_ecc.isSelected()){
                encryptECC();            }
            else if(radio_bloFsh.isSelected()){
                txtArea_result.setText(encryptBlowfish(txt_data.getText(), SALT));
            }
            else {
                Alert alert = new Alert(Alert.AlertType.ERROR);
                alert.setContentText("Please select an Encryption type");
                alert.setHeaderText(null);
                alert.setTitle("Encrypt");
                alert.showAndWait();
            }
        }

    }
    @FXML
    private void submitFileBtn(MouseEvent event) {
        //check if not empty
        if (txt_key.getText().isEmpty() || txtArea_result.getText().isEmpty()) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setContentText("Please Enter all details");
            alert.setHeaderText("Key / encrypted data is empty");
            alert.setTitle("Encryption");
            alert.showAndWait();
        } else {
            saveData();
        }

    }
    private void clearFields() {
        txt_key.clear();
        txtArea_result.clear();
        txt_data.clear();
    }
    @FXML
    private  String saveData(){
        try {
            String st = "INSERT INTO encrypted_data (sender, filename, size,algorithm, encrypted_file ) VALUES (?,?,?,?,?)";
            preparedStatement = (PreparedStatement) connection.prepareStatement(st);
            preparedStatement.setString(1,preferences.get("sender", "name"));
            preparedStatement.setString(2,preferences.get("filename", "filename"));
            preparedStatement.setString(3, String.valueOf(preferences.getInt("size", 0)));
            preparedStatement.setString(4,preferences.get("algorithm", "algorithm"));
            preparedStatement.setString(5,preferences.get("outfile", "outputfile"));

           // preparedStatement.setString(2, txt_key.getText());
           // preparedStatement.setString(4, txtArea_result.getText());
            preparedStatement.executeUpdate();
            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setContentText("Successfully Saved Uploaded ");
            alert.setHeaderText("Done!");
            alert.setTitle("Signup");
            alert.showAndWait();
            //clear fields
            clearFields();
            return "Success";

        } catch (SQLException ex) {
            System.out.println(ex.getMessage());
            //lblStatus.setText(ex.getMessage());
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setContentText(ex.getMessage());
            alert.setHeaderText("Error in saving data");
            alert.setTitle("Signup");
            alert.showAndWait();
            return "Exception";
        }

    }



    @FXML
    private void radio_aes(MouseEvent event) throws IOException {
        radio_aes.setSelected(true);
        radio_3des.setSelected(false);
        radio_des.setSelected(false);
        radio_rsa.setSelected(false);
        radio_bloFsh.setSelected(false);
        radio_ecc.setSelected(false);
        preferences.put("algorithm", radio_ecc.getText());
    }

    @FXML
    private void radio_tdes(MouseEvent event) {
        radio_3des.setSelected(true);
        radio_aes.setSelected(false);
        radio_des.setSelected(false);
        radio_rsa.setSelected(false);
        radio_bloFsh.setSelected(false);
        radio_ecc.setSelected(false);
        preferences.put("algorithm", radio_3des.getText());

    }

    @FXML
    private void radio_rsa(MouseEvent event) {
        radio_rsa.setSelected(true);
        radio_3des.setSelected(false);
        radio_des.setSelected(false);
        radio_aes.setSelected(false);
        radio_bloFsh.setSelected(false);
        radio_ecc.setSelected(false);
        preferences.put("algorithm", radio_rsa.getText());

    }

    @FXML
    private void radio_des(MouseEvent event) {
        radio_des.setSelected(true);
        radio_rsa.setSelected(false);
        radio_3des.setSelected(false);
        radio_aes.setSelected(false);
        radio_bloFsh.setSelected(false);
        radio_ecc.setSelected(false);
        preferences.put("algorithm", radio_des.getText());

    }

    @FXML
    private void radio_ecc(MouseEvent event) {
        radio_ecc.setSelected(true);
        radio_rsa.setSelected(false);
        radio_3des.setSelected(false);
        radio_aes.setSelected(false);
        radio_bloFsh.setSelected(false);
        radio_des.setSelected(false);
        preferences.put("algorithm", radio_ecc.getText());


    }

    @FXML
    private void radio_bloFsh(MouseEvent event) {
        radio_bloFsh.setSelected(true);
        radio_ecc.setSelected(false);
        radio_rsa.setSelected(false);
        radio_3des.setSelected(false);
        radio_aes.setSelected(false);
        radio_des.setSelected(false);
        preferences.put("algorithm", radio_bloFsh.getText());

    }



    private ObservableList<ObservableList> data;
    String SQL = "SELECT * from encrypted_data";
    public void buildData(){
        data = FXCollections.observableArrayList();
        try{
            //SQL FOR SELECTING ALL OF CUSTOMER
            String SQL = "SELECT * from encrypted_data";
            //ResultSet
            ResultSet rs = connection.createStatement().executeQuery(SQL);

            /**********************************
             * TABLE COLUMN ADDED DYNAMICALLY *
             **********************************/
            for(int i=0 ; i<rs.getMetaData().getColumnCount(); i++){
                //We are using non property style for making dynamic table
                final int j = i;
                TableColumn col = new TableColumn(rs.getMetaData().getColumnName(i+1));
                col.setCellValueFactory(new Callback<TableColumn.CellDataFeatures<ObservableList,String>,ObservableValue<String>>(){
                    public ObservableValue<String> call(TableColumn.CellDataFeatures<ObservableList, String> param) {
                        return new SimpleStringProperty(param.getValue().get(j).toString());
                    }
                });

               // tableview.getColumns().addAll(col);
                System.out.println("Column ["+i+"] ");
            }

            /********************************
             * Data added to ObservableList *
             ********************************/
            while(rs.next()){
                //Iterate Row
                ObservableList<String> row = FXCollections.observableArrayList();
                for(int i=1 ; i<=rs.getMetaData().getColumnCount(); i++){
                    //Iterate Column
                    row.add(rs.getString(i));
                }
                System.out.println("Row [1] added "+row );
                data.add(row);

            }

            //FINALLY ADDED TO TableView
           //tableview.setItems(data);
        }catch(Exception e){
            e.printStackTrace();
            System.out.println("Error on Building Data");
        }
    }
}
















/*
    @FXML
    private TextField txtFirstname;
    @FXML
    private TextField txtLastname;
    @FXML
    private TextField txtEmail;
    @FXML
    private DatePicker txtDOB;
    @FXML
    private Button btnSave;
    @FXML
    private ComboBox<String> txtGender;
    @FXML
    Label lblStatus;

    @FXML
    TableView tblData;


    PreparedStatement preparedStatement;
    Connection connection;

    public HomeController() {
        connection = (Connection) ConnectionUtil.conDB();
    }

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // TODO
        txtGender.getItems().addAll("Male", "Female", "Other");
        txtGender.getSelectionModel().select("Male");
        fetColumnList();
        fetRowList();

    }

    @FXML
    private void HandleEvents(MouseEvent event) {
        //check if not empty
        if (txtEmail.getText().isEmpty() || txtFirstname.getText().isEmpty() || txtLastname.getText().isEmpty() || txtDOB.getValue().equals(null)) {
            lblStatus.setTextFill(Color.TOMATO);
            lblStatus.setText("Enter all details");
        } else {
            saveData();
        }

    }

    private void clearFields() {
        txtFirstname.clear();
        txtLastname.clear();
        txtEmail.clear();
    }

    private String saveData() {

        try {
            String st = "INSERT INTO wip_users ( firstname, lastname, email, gender, dob) VALUES (?,?,?,?,?)";
            preparedStatement = (PreparedStatement) connection.prepareStatement(st);
            preparedStatement.setString(1, txtFirstname.getText());
            preparedStatement.setString(2, txtLastname.getText());
            preparedStatement.setString(3, txtEmail.getText());
            preparedStatement.setString(4, txtGender.getValue().toString());
            preparedStatement.setString(5, txtDOB.getValue().toString());

            preparedStatement.executeUpdate();
            lblStatus.setTextFill(Color.GREEN);
            lblStatus.setText("Added Successfully");

            fetRowList();
            //clear fields
            clearFields();
            return "Success";

        } catch (SQLException ex) {
            System.out.println(ex.getMessage());
            lblStatus.setTextFill(Color.TOMATO);
            lblStatus.setText(ex.getMessage());
            return "Exception";
        }
    }

    private ObservableList<ObservableList> data;
    String SQL = "SELECT * from wip_users";

    //only fetch columns
    private void fetColumnList() {

        try {
            ResultSet rs = connection.createStatement().executeQuery(SQL);

            //SQL FOR SELECTING ALL OF CUSTOMER
            for (int i = 0; i < rs.getMetaData().getColumnCount(); i++) {
                //We are using non property style for making dynamic table
                final int j = i;
                TableColumn col = new TableColumn(rs.getMetaData().getColumnName(i + 1).toUpperCase());
                col.setCellValueFactory(new Callback<CellDataFeatures<ObservableList, String>, ObservableValue<String>>() {
                    public ObservableValue<String> call(CellDataFeatures<ObservableList, String> param) {
                        return new SimpleStringProperty(param.getValue().get(j).toString());
                    }
                });

                tblData.getColumns().removeAll(col);
                tblData.getColumns().addAll(col);

                System.out.println("Column [" + i + "] ");

            }

        } catch (Exception e) {
            System.out.println("Error " + e.getMessage());

        }
    }

    //fetches rows and data from the list
    private void fetRowList() {
        data = FXCollections.observableArrayList();
        ResultSet rs;
        try {
            rs = connection.createStatement().executeQuery(SQL);

            while (rs.next()) {
                //Iterate Row
                ObservableList row = FXCollections.observableArrayList();
                for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
                    //Iterate Column
                    row.add(rs.getString(i));
                }
                System.out.println("Row [1] added " + row);
                data.add(row);

            }

            tblData.setItems(data);
        } catch (SQLException ex) {
            System.err.println(ex.getMessage());
        }
    }
*/

