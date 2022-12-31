import sys
import os
import boto3
import hmac, hashlib, base64 
import requests 
from PyQt5.uic import loadUi
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QApplication, QWidget
from PyQt5.QtGui import QPixmap, QPalette, QColor

# Create a Cognito client
client = boto3.client('cognito-idp')

# Set the user pool ID and client ID
user_pool_id = 'us-west-2_lCS5u9L1e'
client_id = '4p7on4hpdseukqniuhohhh33gs'
user_name = 'awsTesting+rmtar2@zeoshi.com'
p_word = 'uGlLP44@9%gZ'
client_secret = '1i55m9r40ld59liifetogjuhm4k16hqdd7n4e7bv8g5djbq8oniu'

def calculate_secret_hash(client_id, client_secret):
    message = bytes(user_name+client_id,'utf-8') 
    key = bytes(client_secret,'utf-8') 
    secret_hash = base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()
    return secret_hash 
    
def init_auth(user_name, p_word):
    secret_hash = calculate_secret_hash(client_id, client_secret)
    auth_parameters = {
        'SECRET_HASH': secret_hash,
        'USERNAME': user_name,
        'PASSWORD': p_word
    }
    # Call initiate_auth
    auth_obj = client.initiate_auth(
        ClientId=client_id,
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters=auth_parameters
    )
    return auth_obj



class LoginScreen(QDialog):
    def __init__(self):
        super(LoginScreen, self).__init__()
        loadUi(os.path.join(os.path.dirname(os.path.abspath(__file__)), "login.ui"),self)
        self.passwordfield.setEchoMode(QtWidgets.QLineEdit.Password)
        self.login.clicked.connect(self.loginfunction)

    def loginfunction(self):
        user = self.emailfield.text()
        password = self.passwordfield.text()

        if len(user)==0 or len(password)==0:
            self.error.setText("Please input all fields.")

        else:
            auth_tokens = init_auth(user_name, p_word)
            # print('IdToken:', auth_tokens['AuthenticationResult']['IdToken'])]
            # # if result_pass == password:
            # #     print("Successfully logged in.")
            # #     self.error.setText("")
            # # else:
            # #     self.error.setText("Invalid username or password")


            # # query processing api
            # url = "https://us-west-2.api.zeoshi.com/dev/processing"
            # headers = {
            #     "Authorization": auth_tokens['AuthenticationResult']['IdToken']
            # }
            # body = {
            #     'operation': 'echo'
            # }

            # # Make the request to the API
            # response = requests.post(url, headers=headers, json=body)

            # # Print the response from the API
            # print(response)


# class CreateAccScreen(QDialog):
#     def __init__(self):
#         super(CreateAccScreen, self).__init__()
#         loadUi("createacc.ui",self)
#         self.passwordfield.setEchoMode(QtWidgets.QLineEdit.Password)
#         self.confirmpasswordfield.setEchoMode(QtWidgets.QLineEdit.Password)
#         self.signup.clicked.connect(self.signupfunction)

#     def signupfunction(self):
#         user = self.emailfield.text()
#         password = self.passwordfield.text()
#         confirmpassword = self.confirmpasswordfield.text()

#         if len(user)==0 or len(password)==0 or len(confirmpassword)==0:
#             self.error.setText("Please fill in all inputs.")

#         elif password!=confirmpassword:
#             self.error.setText("Passwords do not match.")
#         else:
#             conn = sqlite3.connect("shop_data.db")
#             cur = conn.cursor()

#             user_info = [user, password]
#             cur.execute('INSERT INTO login_info (username, password) VALUES (?,?)', user_info)

#             conn.commit()
#             conn.close()

#             fillprofile = FillProfileScreen()
#             widget.addWidget(fillprofile)
#             widget.setCurrentIndex(widget.currentIndex()+1)

# class FillProfileScreen(QDialog):
#     def __init__(self):
#         super(FillProfileScreen, self).__init__()
#         loadUi("fillprofile.ui",self)
#         self.image.setPixmap(QPixmap('placeholder.png'))



# main
app = QApplication(sys.argv)
login = LoginScreen()
widget = QtWidgets.QStackedWidget()
widget.addWidget(login)
widget.setFixedHeight(800)
widget.setFixedWidth(1200)
widget.show()
try:
    sys.exit(app.exec_())
except:
    print("Exiting")