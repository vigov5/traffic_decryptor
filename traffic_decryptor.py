from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, ITab
from java.io import PrintWriter
from javax.swing import JPanel, JButton, JFrame, BoxLayout, Box
from java.awt import Dimension, BorderLayout
from java.awt.event import ActionListener

import json
import base64

# import encrypt/decrypt logic
import imp
import logic
import traceback


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        # Set up extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Traffic Decryptor")

        # Create the UI
        self._createUI()

        # Add the custom tab to Burp's UI
        self._callbacks.addSuiteTab(self)

        # Register message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        # Set up stdout
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stdout.println("Traffic Decryptor extension loaded")

    def getTabCaption(self):
        return "Traffic Decryptor"

    def getUiComponent(self):
        return self._panel

    def _createUI(self):
        # Create the main panel with BorderLayout
        self._panel = JPanel(BorderLayout())

        # Create a button
        self.btnReload = JButton("Reload", actionPerformed=self.btnReload_clicked)
        self.btnReload.setPreferredSize(Dimension(400, 200))  # Set button size

        # Create a panel with BoxLayout to center the button
        buttonPanel = JPanel()
        buttonPanel.setLayout(BoxLayout(buttonPanel, BoxLayout.Y_AXIS))

        # Create a horizontal box to center the button horizontally
        horizontalBox = JPanel()
        horizontalBox.setLayout(BoxLayout(horizontalBox, BoxLayout.X_AXIS))
        horizontalBox.add(Box.createHorizontalGlue())
        horizontalBox.add(self.btnReload)
        horizontalBox.add(Box.createHorizontalGlue())

        # Add the horizontal box to the button panel
        buttonPanel.add(Box.createVerticalGlue())
        buttonPanel.add(horizontalBox)
        buttonPanel.add(Box.createVerticalGlue())

        # Add the button panel to the main panel
        self._panel.add(buttonPanel, BorderLayout.CENTER)

    def btnReload_clicked(self, e=None):
        self.stdout.println("Reloading logic...")
        imp.reload(logic)

    def createNewInstance(self, controller, editable):
        # Create a new instance of the message editor tab
        return TrafficDecryptorTab(self, controller, editable, self.stdout)


class TrafficDecryptorTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable, stdout):
        self._extender = extender
        self._controller = controller
        self._editable = editable
        self._helpers = extender._helpers
        self._stdout = stdout

        # Create a text editor
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(True)
        self._currentMessage = None
        self._originalMessage = None
        self._isRequest = None

    def getTabCaption(self):
        return "Traffic Decryptor"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        # Enable this tab for all requests/responses
        return True

    def setMessage(self, content, isRequest):
        if content is None:
            self._txtInput.setText(None)
            self._currentMessage = None
            self._originalMessage = None
            self._isRequest = None
            return

        # Store the original message
        self._originalMessage = content
        self._currentMessage = content
        self._isRequest = isRequest

        # Parse the content
        try:
            if logic.is_encrypted(self, content, isRequest):
                if isRequest:
                    logic.set_request_text(self, content, isRequest)
                else:
                    logic.set_response_text(self, content, isRequest)
            else:
                logic.set_not_encrypted_text(self, content, isRequest)
        except Exception as e:
            logic.set_error_text(self, e)
            if logic.is_debug(self):
                traceback.print_exc(file=self._stdout)

    def getMessage(self):
        # If the custom tab was modified, re-encode the data field before returning the message
        if logic.is_text_modified(self):
            try:
                if self._isRequest:
                    message = logic.build_request(self)
                else:
                    message = logic.build_response(self)

                return message
            except Exception as e:
                self._stdout.println("Error re-encoding data: {}".format(e))
                if logic.is_debug(self):
                    traceback.print_exc(file=self._stdout)

        # Return the possibly modified message
        return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()
