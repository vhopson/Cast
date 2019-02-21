import argparse
import xml.etree.cElementTree as ET
import datetime
import tempfile
import os
import sys
from collections import Counter
import re

## Filter the input XML file from CAST
#
#
def castFilter(in_xml, tmp) :
	# get each individual line in the input file and process it.
	line_counter = 0
	for line in in_xml :
		line_counter += 1
		
		# skip the initial line of the XML file
		if line.find("<?xml version") != -1 :
			tmp.write(line)
			continue
			
		# clean the lines that begin and end with an apostrophe
		if line[0] == "\'" :
			line = line[1:line.rindex("\'")]
		
		# check to see if each line has an equal count of "<", and ">"
		cnts = Counter(line)
		if cnts["<"] != cnts[">"] :
			# process the line further.  Unequal "<", and ">" counts on this line
			# We place the missing ">" after the "type" attribute.  We search for the
			# location and replace it.
			indx = line.split('type=\"', 1)
			back_indx = indx[1].split('\"', 1)
			line = indx[0] + 'type=\"' + back_indx[0] + '\">' + back_indx[1]
		
		# search for a filename with angle brackets on the line if it exists.
		# we substitute "&lt;" for "<", and "&gt;" for ">"
		fn = line.split("fullname=\"", 1)
		if len(fn) > 1  :
			# diagnostic
			# are there any offending characters?
			parm = fn[1].split("\"", 1)
			
			if parm[0].find("<") > -1 :
				parm[0] = parm[0].replace("<", "&lt;")
				parm[0] = parm[0].replace(">", "&gt;")
				line = fn[0] + "fullname=\"" + parm[0] + "\"" + parm[1]

		# write the line into our temporary file
		tmp.write(line)

## Invocation in "pass through" mode.
#
# Do not filter the input file.  Simply write the file to output
def passThrough(tmp, outfile) :
	for line in tmp :
		outfile.write(line)

## Process the XML information
#
#
def processCastXML(tmp, outfile) :
	# begin the parsing of information for Code Dx transformation
	tree = ET.parse(tmp)
	root = tree.getroot()
	
	# The root of a CAST XML report has a UTC date we can use for the report.
	# We grab that and the version of CAST
	cast_version = root.attrib["version"]
	report_date = root.attrib["timestamp"]
	
	# begin building the Code Dx XML by generating the beginning artifacts
	xml_report = ET.Element("report", { "date" : report_date })
	xml_findings = ET.SubElement(xml_report, "findings")
	
	# cycle through the incoming findings.  We will set all criticalities to
	# a default of "Medium" if no severity is specified.
	for file in root.iter("file") :
		# get the "violation" element from the input CAST records
		file_violation = file.find("violation")
		
		# build the output element for Code Dx (tool record)
		xml_finding = ET.SubElement(xml_findings, "finding", { "severity" : "medium" })
		tool_attribs = {
			"name" : "CAST",
			"category" : file_violation.attrib["ruleset"],
			"code" : file_violation.attrib["fullname"] }
		ET.SubElement(xml_finding, "tool", tool_attribs)
		
		# build the location record
		location_attribs = {
			"type" : "file",
			"path" : file.attrib["name"].replace("\\", "/") }
		xml_location = ET.SubElement(xml_finding, "location", location_attribs)
		line_attribs = {
			"start" : file_violation.attrib["beginline"],
			"end"   : file_violation.attrib["endline"] }
		ET.SubElement(xml_location, "line", line_attribs)
		xml_description = ET.SubElement(xml_finding, "description", { "format" : "plain-text" } )
		xml_description.text = file_violation.text
		
		# if the text in the "file" object has "CWE-", extract it
		cwe_detect = file_violation.text.split("CWE-", 1)
		if len(cwe_detect) > 1 :
			cwenum_re = re.compile("(\d+)")
			cwe_value = cwenum_re.search(cwe_detect[1])
			ET.SubElement(xml_finding, "cwe", { "id" : cwe_value.group(0) })
			
	
	# We have built the entire conversion in memory.  Write it out
	tree = ET.ElementTree(xml_report)
	tree.write(outfile, xml_declaration=True, encoding='utf-8')
	
## Main Entry Point
#
def main(args) :

	# open the input file and send it to a CAST XML filter
	print "- Beginning operation"
	print "|- Opening \"" + args.input + "\" for CAST input XML data"
	in_file = open(args.input, "r")
	fd, temp_file = tempfile.mkstemp()
	tmp = os.fdopen(fd, "w")
	
	# filter the XML before parsing
	if castFilter(in_file, tmp) == False :
		print "|- castFilter failed."
		
	else :
		print "|- Opening filtered CAST XML temporary file \"" + temp_file + "\""
		tmp.close()
		tmp = open(temp_file, "r")
		
		print "|- Opening output file \"" + args.output + "\""
		outfile = open(args.output, "w")
		
		if args.passthru == False :
			print "|- Begin processing filtered CAST XML information"
			processCastXML(tmp, outfile)
		else :
			print "|- Processing in PASSTHROUGH mode.  No Code Dx conversion"
			passThrough(tmp, outfile)
		
		print "|- Closing the input output file \"" + args.output + "\""
		outfile.close()

	# Cleaning up and exiting
	print "++ Cleaning up"
	in_file.close()
	print "|- Deleting temporary file \"" + temp_file + "\""
	tmp.close()
	os.remove(temp_file)
	
## Environmental Set up
#
parser = argparse.ArgumentParser()
parser.add_argument("--input",    "-i", required=True,  help="Input CAST XML file.")
parser.add_argument("--output",   "-o", required=True,  help="Code Dx formatted XML file.")
parser.add_argument("--passthru", "-p", required=False, action="store_true", default=False, help="Pass CAST XML with filtering. No conversion")
args = parser.parse_args()

if __name__ == "__main__" :
	main(args)

