"""
tab._extender
tab._controller
tab._editable
tab._helpers
tab._stdout
tab._txtInput
tab._originalMessage
tab._isRequest
"""

DEBUG = True

REQUEST_LAYOUT = {
    "data": ""
}

RESPONSE_LAYOUT = {
    "data": "",
    "error": 0
}

import json
import copy
import base64
import traceback
import pyaes


def is_debug(tab):
    # tab._stdout.println("Is Debug?: {}".format(DEBUG))
    return DEBUG


# contain detection logic, return True if this request/response contains ecrypted data
def is_encrypted(tab, content, isRequest):
    info, body = extract_info(tab, content, isRequest)
    body = content[info.getBodyOffset() :].tostring()
    json_data = json.loads(body)

    if is_debug(tab):
        tab._stdout.println("Is Encrypted?: {}".format("data" in json_data))
        tab._stdout.println("Original data: {}".format(body))

    return "data" in json_data


# contain logic for decrypt request traffic, call setText with decrypted data
def set_request_text(tab, content, isRequest):
    info, body = extract_info(tab, content, isRequest)
    body = content[info.getBodyOffset() :].tostring()
    json_data = json.loads(body)
    
    decrypted = decrypt_data(json_data["data"])
    
    tab._txtInput.setText(decrypted.encode("utf-8"))


# contain logic for decrypt response traffic, call setText with decrypted data
def set_response_text(tab, content, isRequest):
    set_request_text(tab, content, isRequest)


def set_error_text(tab, e):
    # tab._txtInput.setText("Error processing content: {}".format(e).encode("utf-8"))
    tab._txtInput.setText(traceback.format_exc())


def set_not_encrypted_text(tab, content, isRequest):
    return tab._txtInput.setText("No encrypted data found!")


def is_text_modified(tab):
    if is_debug(tab):
        tab._stdout.println("Edited?: {}".format(tab._txtInput.isTextModified()))

    return tab._txtInput.isTextModified()


def build_request(tab):
    # call this to get current text in editor
    text = tab._txtInput.getText()

    # process content
    json_data = json.loads(text.tostring())
    encoded_data = encrypt_data(json.dumps(json_data))
    
    if tab._isRequest:
        layout = REQUEST_LAYOUT
    else:
        layout = RESPONSE_LAYOUT

    new_body = copy.deepcopy(layout)
    layout["data"] = encoded_data
    new_body = json.dumps(new_body)

    if is_debug(tab):
        tab._stdout.println("Re-encoded data: {}".format(new_body))

    # build new message
    info, body = extract_info(tab, tab._originalMessage, tab._isRequest)
    headers = info.getHeaders()
    tab._currentMessage = tab._helpers.buildHttpMessage(headers, new_body)

    return tab._currentMessage


def build_response(tab):
    return build_request(tab)

# ENCRYPT / DECRYPT

def decrypt_data(encrypted_data):
    encrypted_data_bytes = base64.b64decode(encrypted_data)
    decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(b"thisisakey123456", b"thisisaniv123456"))
    decrypted_data = decrypter.feed(encrypted_data_bytes) + decrypter.feed()

    return decrypted_data.decode('utf-8')

def encrypt_data(plaintext):
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(b"thisisakey123456", b"thisisaniv123456"))
    ciphertext = encrypter.feed(plaintext.encode('utf-8')) + encrypter.feed()
    encrypted_data = base64.b64encode(ciphertext).decode('utf-8')

    return encrypted_data

# HELPERS


def extract_info(tab, content, isRequest):
    if isRequest:
        info = tab._helpers.analyzeRequest(content)
    else:
        info = tab._helpers.analyzeResponse(content)

    body = content[info.getBodyOffset() :].tostring()

    return info, body
