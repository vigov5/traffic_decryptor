from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json

app = Flask(__name__)

# AES-128 requires a 16-byte (128-bit) key
AES_KEY = b"thisisakey123456"  # Default key (should be kept secret in production)
AES_IV = b"thisisaniv123456"   # Initialization Vector (IV), should also be 16 bytes

def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decoded_encrypted_data = base64.b64decode(encrypted_data)
    decrypted_padded_data = cipher.decrypt(decoded_encrypted_data)
    decrypted_data = unpad(decrypted_padded_data, AES.block_size)
    return decrypted_data.decode('utf-8')

@app.route('/status', methods=['GET'])
def status():
    response_data = {
        "name": "Demo Encrypted Traffic Server",
        "version": "0.1"
    }
    json_response = jsonify(response_data).get_data(as_text=True)
    encrypted_data = encrypt_data(json_response)
    return jsonify({"error": 0, "data": encrypted_data})

@app.route('/hello', methods=['POST'])
def hello():
    try:
        request_data = request.get_json()
        encrypted_data = request_data.get('data')
        decrypted_json = decrypt_data(encrypted_data)
        decrypted_data = json.loads(decrypted_json)

        if 'name' in decrypted_data:
            name = decrypted_data['name']
            response_message = {"resp": f"Hello {name}!"}
            json_response = json.dumps(response_message)
            encrypted_response = encrypt_data(json_response)
            return jsonify({"error": 0, "data": encrypted_response})
        else:
            return jsonify({"error": 1, "message": "Key 'name' not found in decrypted data"}), 400
    except Exception as e:
        return jsonify({"error": 1, "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
