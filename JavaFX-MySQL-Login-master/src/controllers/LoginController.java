package controllers;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
import java.io.IOException;
import java.net.URL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ResourceBundle;
import java.util.prefs.Preferences;

import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import utils.ConnectionUtil;

/**
 *
 * @author oXCToo
 */
public class LoginController implements Initializable {

    @FXML
    private Label lblErrors;

    @FXML
    private TextField txtUsername;

    @FXML
    private TextField txtPassword;

    @FXML
    private Button btnSignin;

    /// -- 
    Connection con = null;
    PreparedStatement preparedStatement = null;
    ResultSet resultSet = null;
    Preferences preferences=Preferences.userRoot();
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // TODO
        if (con == null) {
            lblErrors.setTextFill(Color.TOMATO);
            lblErrors.setText("Server Error : Check");
        } else {
            lblErrors.setTextFill(Color.GREEN);
            lblErrors.setText("Server is up : Good to go");
        }
    }

    @FXML
    public void handleButtonAction(MouseEvent event) {

        if (event.getSource() == btnSignin) {
            //login here
            if (logIn().equals("Success")) {
                try {

                    //add you loading or delays - ;-)
                   Node node = (Node) event.getSource();
                   Stage stage = (Stage) node.getScene().getWindow();
                   // stage.setMaximized(true);
                    //stage.close();
                   // Scene scene = new Scene(FXMLLoader.load(getClass().getResource("/fxml/Home.fxml")));
                    Parent root = FXMLLoader.load(getClass().getResource("/fxml/Home.fxml"));

                    Scene scene = new Scene(root);

                    stage.setScene(scene);
                    stage.show();
                    stage.setScene(scene);
                    stage.show();


                } catch (IOException ex) {
                    System.err.println(ex.getMessage());
                    System.out.println("Error in Home.fxml" + ex.getMessage());
                }

            }
        }
    }
 @FXML
 public void signupButton(MouseEvent  event){
     try {
         //add you loading or delays - ;-)
         Node node = (Node) event.getSource();
         Stage stage = (Stage) node.getScene().getWindow();
         //stage.setMaximized(true);
         stage.close();
         Scene scene = new Scene(FXMLLoader.load(getClass().getResource("/fxml/SignUp.fxml")));
         stage.setScene(scene);
         stage.show();

     } catch (IOException ex) {
         System.err.println(ex.getMessage());
     }
 }


    public LoginController() {
        con = ConnectionUtil.conDB();
    }

    //we gonna use string to check for status
    private String logIn() {
        String status = "Success";
        String email = txtUsername.getText();
        String password = txtPassword.getText();
        if(email.isEmpty() || password.isEmpty()) {
            setLblError(Color.TOMATO, "Empty credentials");
            status = "Error";
        } else {
            //query
            String sql = "SELECT * FROM users Where email = ? and password = ?";
            try {
                preparedStatement = con.prepareStatement(sql);
                preparedStatement.setString(1, email);
                preparedStatement.setString(2, password);
                resultSet = preparedStatement.executeQuery();
                if (!resultSet.next()) {
                    setLblError(Color.TOMATO, "Enter Correct Email/Password");
                    status = "Error";
                } else {
                    preferences.put("sender", resultSet.getString(2));
                    setLblError(Color.GREEN, "Login Successful..Redirecting..");
                }
            } catch (SQLException ex) {
                System.err.println(ex.getMessage());
                status = "Exception";
            }
        }
        
        return status;
    }
    
    private void setLblError(Color color, String text) {
        lblErrors.setTextFill(color);
        lblErrors.setText(text);
        System.out.println(text);
    }
}
