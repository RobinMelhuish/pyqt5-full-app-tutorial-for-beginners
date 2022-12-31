import boto3
import hmac, hashlib, base64 
import requests 

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

auth_tokens = init_auth(user_name, p_word)

print('IdToken:', auth_tokens['AuthenticationResult']['IdToken'])

# query processing api
url = "https://us-west-2.api.zeoshi.com/dev/processing"
headers = {
    "Authorization": auth_tokens['AuthenticationResult']['IdToken']
}
body = {
    'operation': 'echo'
}

# Make the request to the API
response = requests.post(url, headers=headers, json=body)

# Print the response from the API
print(response)
