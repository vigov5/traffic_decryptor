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

import traceback


def is_debug(tab):
    # tab._stdout.println("Is Debug?: {}".format(DEBUG))
    return DEBUG


# contain detection logic, return True if this request/response contains ecrypted data
def is_encrypted(tab, content, isRequest):
    return False


# contain logic for decrypt request traffic, call setText with decrypted data
def set_request_text(tab, content, isRequest):
    decrypted = "put_your_decrypted_content_here"
    
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

    new_body = "your_new_body_recreated_from_text_in_editor_here"

    if is_debug(tab):
        tab._stdout.println("Re-encoded data: {}".format(new_body))

    # build new message
    info, body = extract_info(tab, tab._originalMessage, tab._isRequest)
    headers = info.getHeaders()
    tab._currentMessage = tab._helpers.buildHttpMessage(headers, new_body)

    return tab._currentMessage


def build_response(tab):
    return build_request(tab)


# HELPERS


def extract_info(tab, content, isRequest):
    if isRequest:
        info = tab._helpers.analyzeRequest(content)
    else:
        info = tab._helpers.analyzeResponse(content)

    body = content[info.getBodyOffset() :].tostring()

    return info, body
