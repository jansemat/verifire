from pysmt.shortcuts import Symbol, And, Or, Not, get_model, is_sat
from itertools import groupby
from pysmt.typing import BOOL
import numpy as np
import ipaddress
import argparse
import textwrap
import random
import pysmt
import json
import time
import sys
import os


# |-------------------------------------------------------------------- |
# |                      Return formula functions                       |
# |---------------------------------------------------------------------|

# Function: get_int_formula(num, varname, cap)
# --- Arguments: num = number to explicitly form into boolean formula,
#				varname = variable name from config file,
#				cap = number of bits needed to express `num`
# --- Return: boolean formula to express `num`
# --- Purpose: Return a boolean number to express `num` using `cap` bits
#				and using `varname` for the variable names in formula
#
def get_int_formula(num, varname, cap):
	form = []
	bitcap = '0'+str(cap)+'b'
	for i in range(cap):
		if format(num, bitcap)[i] == '1': form.append(Symbol(varname+str(i), BOOL))
		elif format(num, bitcap)[i] == '0': form.append(Not(Symbol(varname+str(i), BOOL)))
	return And(form)


# Function: get_intrange_init(start, end, varname, cap)
# --- Arguments: start,end = start and end of integer range to express in
#				boolean formula
#				varname = variable name from config file,
#				cap = number of bits needed to express `num`
# --- Return: new `start`,`end` values, and a >= 0 length formula
# --- Purpose: If the start variable is odd, or the end variable is even, 
#				Alter the start/end values such that they're even/odd resp. ,
#				and if they're altered, return their boolean formulas
#
def get_intrange_init(start, end, varname, cap):
	if start%2==1 and end%2==0:
		form = Or(get_int_formula(start,varname,cap), get_int_formula(end,varname,cap))
		start, end = start+1, end-1
	elif start%2==1:
		form = get_int_formula(start,varname,cap)
		start += 1
	elif end%2==0:
		form = get_int_formula(end,varname,cap)
		end -= 1

	return start, end, form


# Function: get_intrange_formula(s_idx, start, end, root, varname, cap)
# --- Arguments: s_idx = starting index of the bitstring representations of start/end,
#				start,end = starting/ending values to represent as bool formulas,
#				root = bool - true if root of recursion, false otherwise,
#				varname = variable name from config file,
#				cap = number of bits needed to express `num`
# --- Return: boolean formula which represents the start-end range
# --- Purpose: turn a range of integers into a boolean formula which is true if an
#				int is in that range, and false otherwise
#
def get_intrange_formula(s_idx, start, end, root, varname, cap):
	# init vars
	form = []
	c_idx = 0
	bitcap = '0'+str(cap)+'b'

	# init starting ints
	if end==start and root==True:
		return get_int_formula(start,varname,cap)
	elif end-start==1: 
		return Or(get_int_formula(start,varname,cap), get_int_formula(end,varname,cap))
	elif s_idx == 0 and root == True and (start%2==1 or end%2==0):
		start, end, init = get_intrange_init(start, end, varname, cap)
		form.append(init)

	enum = [format(i, bitcap) for i in range(start, end+1)]
		
	# find midpoint
	temp = []
	for j in range(s_idx, cap):
		c_idx = j
		col = [int(line[j]) for line in enum]
		mid = start + np.count_nonzero(np.array(col)==0)
		is_same = np.all(col) or np.all(np.logical_not(col))
		if is_same and col[0]==0: temp.append(Not(Symbol(varname+str(j),BOOL)))
		if is_same and col[0]==1: temp.append(Symbol(varname+str(j),BOOL))
		if not is_same: break

	if mid%2 == 1:
		if mid-start > end-mid: mid -= 1
		elif mid-start <= end-mid: mid += 1

	# if you don't need to recurse
	if end-start==1:
		if format(start, bitcap)[c_idx] == '0': return And(temp) 
		else: return And(temp) 

	if format(start, bitcap)[(c_idx):] == '0'*(cap-c_idx) and format(end, bitcap)[c_idx:] == '1'*(cap-c_idx):
		if temp != []: return And(temp)
		else: return None

	# otherwise, if you need to recurse
	rec1, rec2 = get_intrange_formula(c_idx, start, mid-1, False, varname, cap), get_intrange_formula(c_idx, mid, end, False, varname, cap)
	or_sec = []
	if rec1 != None: or_sec.append(rec1)
	if rec2 != None: or_sec.append(rec2)
	rec_sec = Or(or_sec)
	if temp != []: form.append(And(And(temp), rec_sec))
	else: form.append(rec_sec)
	return Or(form)


# Function: get_ipv4_formula(addr, cidr, varname)
# --- Arguments: addr = IP address string from field,
#				cidr = integer representation of CIDR mask from field,
#				varname = variable name from config file
# --- Return: conjunctive boolean formula
# --- Purpose: return formula that represents packets with fields that match the IP/CIDR given
#
def get_ipv4_formula(addr, cidr, varname):
	addr_bitstr = ''.join([format(int(i), '08b') for i in addr])[:cidr]
	form = []

	for i in range(len(addr_bitstr)):
		if addr_bitstr[i] == '1': form.append(Symbol(varname+str(i), BOOL))
		elif addr_bitstr[i] == '0': form.append(Not(Symbol(varname+str(i), BOOL)))

	return And(form)


# Function: get_rule_formula(rule, config)
# --- Arguments: rule = CSV string representing a firewall rule,
#				config = dictionary with elements from config.json input file
# --- Return: conjunctive boolean formula
# --- Purpose: return formula that matches packets which match the firewall rule given
#
def get_rule_formula(rule, config):
	rule = rule.split(",")
	rule_form = []

	for i in range(len(config)):
		if i < len(config)-1:
			varname = config[str(i)]["varname"]
			if "max" in config[str(i)]: cap = int(np.ceil(np.log2(config[str(i)]["max"])))
			field = rule[i]
			ipv4, (a,b) = process_field(field)
			if ipv4:
				field_form = get_ipv4_formula(a, b, varname)
			elif not ipv4:
				if a == b: field_form = get_int_formula(a, varname, cap)
				else: field_form = get_intrange_formula(0, a, b, True, varname, cap)
			if field_form != None: rule_form.append(field_form)

	if rule_form == None: 
		return pysmt.shortcuts.Bool(True)
	else:
		return And(rule_form)


# Function: get_firewall_formula(fw_filename, config)
# --- Arguments: fw_filename = filename of firewall policy given as input,
#				config = dictionary with elements from config.json input file
# --- Return: disjunctive boolean formula
# --- Purpose: return formula that matches packets which match a rule in the firewall
#
def get_firewall_formula(fw_filename, config):
	fw_form = []

	with open(fw_filename, "r") as fd:
		fw_rules = fd.read().splitlines()

	p_i = pysmt.shortcuts.Bool(False)
	for rule in fw_rules:
		r_i = get_rule_formula(rule, config)
		m_i = And(r_i, Not(p_i))
		if rule.split(",")[-1] == "allow":
			fw_form.append(m_i)
		p_i = Or(p_i, m_i)

	return Or(fw_form)


# Function: get_discardslice_formula(ds_filename, config)
# --- Arguments: ds_filename = filename of discard slice given as input,
#				config = dictionary with elements from config.json input file
# --- Return: dijunctive boolean formula
# --- Purpose: return formula that matches packets which match a rule in the slice
#
def get_discardslice_formula(ds_filename,config):
	rule_form = []

	with open(ds_filename, "r") as fd:
		ds_rules = fd.read().splitlines()[:-1]

	for line in ds_rules:
		rule_form.append(get_rule_formula(line, config))

	return Or(rule_form)


# Function: get_fvd_formula(ds_filename, fw_filename, config)
# --- Arguments: ds_filename = filename of discard slice given as input,
#				fw_filename = filename of firewall policy given as input,
#				config = dictionary with elements from config.json input file
# --- Return: boolean formula
# --- Purpose: return formula that is UNSAT if ds(pkt)=0 ==> fw(pkt)=0, and SAT otherwise
#
def get_fvd_formula(ds_filename, fw_filename, config):
	# ds formula: 
	ds_form = get_discardslice_formula(ds_filename, config)
	# firewall formula:
	fw_form = get_firewall_formula(fw_filename, config)
	return And(Not(ds_form), fw_form)


# |-------------------------------------------------------------------- |
# |                        Verify functions                             |
# |---------------------------------------------------------------------|

# Function: verify_model2packet_int(i_vals)
# --- Arguments: i_vals = boolean array from model representing an integer
# --- Return: field integer (string)
# --- Purpose: helper function for verify_model2packet(), which converts bool array to int
#
def verify_model2packet_int(i_vals):
	bitcap = len(i_vals)
	bitstr = ''.join([str(int(j == True)) for (i,j) in i_vals])
	intstr = str(int(bitstr,2))
	return intstr


# Function: verify_model2packet_ipv4(i_vals)
# --- Arguments: i_vals = boolean array from model representing an IPv4 addr
# --- Return: field IP address (string)
# --- Purpose: helper function for verify_model2packet(), which converts bool array to IPv4 addr
#
def verify_model2packet_ipv4(i_vals):
	bitstr = ''.join([str(int(j == True)) for (i,j) in i_vals])
	ip = '.'.join([str(int(bitstr[i:i+8],2)) for i in range(0,len(bitstr),8)])
	return ip


# Function: verify_model2packet(model, config)
# --- Arguments: model = pysmt model representing a satisfying assignment of boolean variables,
#				config = dictionary with elements from config.json input file
# --- Return: network packet represented by a CSV string
# --- Purpose: Transform a satifying boolean assignment into a network packet
#
def verify_model2packet(model, config):
	packet_str = []
	for i in config:
		if config[i]["type"] == "decision": break
		if config[i]["type"] == "int_range": bitcap = int(np.ceil(np.log2(config[i]["max"])))
		elif config[i]["type"] == "ipv4": bitcap = 32
		i_syms = [Symbol((config[i]["varname"] + str(j)),BOOL) for j in range(bitcap)]
		i_vals = [(j, model.get_py_value(j)) for j in i_syms]
		if config[i]["type"] == "ipv4":
			packet_str += [verify_model2packet_ipv4(i_vals)]
		elif config[i]["type"] == "int_range":
			packet_str += [verify_model2packet_int(i_vals)]

	return ','.join(packet_str)



# Function: verify_print_results(slice_fn, fw_fn, sat, pkt, form_t, sat_t, mod_t)
# --- Arguments: slice_fn = filename for discard slice, fw_fn = filename for firewall policy,
#				sat = True/False if FV-D holds for discard_slice/firewall,
#				pkt = if unsat, example packet that would be denied by slice but accepted by FW,
#				form_t, sat_t, mod_t = times to create formula, find SAT/UNSAT, and create model
# --- Return: Nothing
# --- Purpose: Print results of FV-D testing
#
def verify_print_results(slice_fn, fw_fn, sat, pkt, form_t, sat_t, mod_t):
	print("- Inputs:")
	print("-- Discard slice: " + slice_fn)
	print("-- Firewall policy: " + fw_fn)
	print("- Output:")
	if sat:
		print("-- Verification failed: there exists a packet denied by discard slice, but allowed by FW policy")
		print("-- Sample packet: " + pkt)
		print("- Statistics:")
		print("-- Time to create formula: " + str(form_t) + "s")
		print("-- Time to check satisfiability (verify formula): " + str(sat_t) + "s")
		print("-- Time to create packet: " + str(mod_t) + "s")
	else:
		print("-- Verification succeeded: all packets denied by discard slice are also denied by FW policy")
		print("- Statistics:")
		print("-- Time to create formula: " + str(form_t) + "s")
		print("-- Time to check satisfiability (verify formula): " + str(sat_t) + "s")

	print("")
	return


# Function: run_verify(discard_slice, firewall, config)
# --- Arguments: discard_slice = filename for discard slice input from user,
#				firewall = filename for firewall input from user,
#				config = dictionary of configuration details
# --- Return: Nothing
# --- Purpose: Run discard verification on discard_slice/firewall pair
#
def run_verify(discard_slice, firewall, config):
	model, pkt, mod_t = False, "", 0.0

	# time to get formula
	form_t1 = time.time()
	form = get_fvd_formula(discard_slice, firewall, config)
	form_t = time.time() - form_t1

	# time to check sat/unsat of formula
	sat_t1 = time.time()
	sat = is_sat(form)
	sat_t = time.time() - sat_t1

	# if sat, time to create witness
	if sat:
		mod_t1 = time.time()
		model = get_model(form)
		mod_t = time.time() - mod_t1
		pkt = verify_model2packet(model, config)
	
	# print results
	verify_print_results(discard_slice, firewall, sat, pkt, form_t, sat_t, mod_t)



# |-------------------------------------------------------------------- |
# |                     Utility / Driver functions                      |
# |---------------------------------------------------------------------|


# Function: verify_check(discard_slice, firewall)
# --- Arguments: discard_slice = input filename for discard slice, 
#				firewall = input filename for firewall
# --- Return: True if both files exist, otherwise throw error
# --- Purpose: Check that both the input files exist before continuing
#
def verify_check(discard_slice, firewall):
	if not os.path.isfile(discard_slice):
		sys.exit("PRE-CHECK: The discard slice input file `" + discard_slice + "` does not exist.")
	if not os.path.isfile(firewall):
		sys.exit("PRE-CHECK: The firewall input file `" + firewall + "` does not exist.")
	return True


# Function: process_field(field)
# --- Arguments: field = specific field from discard slice / firewall rule[idx]
# --- Return: If field is ipv4/cidr format, then return value is (True, (ipv4_addr, CIDR_mask)),
#				If field is int/hex range, then return value is (False, (int_min, int_max)),
#				Otherwise, return error
# --- Purpose: Validate field values before boolean formula computed
#
def process_field(field):
	field_copy = field
	ipv4 = False

	# First, determine if CIDR format or int range (or hex range)
	try:
		if "/" in field: # either ipv4 address or hex range
			field = field.split("/")
			if len(field) == 2 and "0x" in field[0] and "0x" in field[1]: # its a hex range
				a,b = int(field[0],16), int(field[1],16)
			elif len(field) == 2: # its an ipv4 cidr range
				_ = ipaddress.ip_address(field[0])
				addr, cidr = field[0].split("."), int(field[1])
				if cidr > 32 or cidr < 0:
					sys.exit("INPUT ERR: Invalid cidr range, " + field_copy)
				if ''.join([format(int(octet),'08b') for octet in addr])[cidr:] != '0'*(32-cidr):
					sys.exit(("INPUT ERR: Invalid cidr range, " + field_copy))
				ipv4 = True
		elif "-" in field: # either a hex range or int range
			if "0x" in field: # hex range
				a,b = int(field.split("-")[0],16), int(field.split("-")[1],16)
			else: # int range
				a,b = int(field.split("-")[0]), int(field.split("-")[1])
		elif "." in field: # single ip address
			_ = ipaddress.ip_address(field)
			addr, cidr = field, 32
		else: #single int
			a,b = int(field), int(field)
	except: # else, oops cant parse
		sys.exit("Error in parsing field: " + field_copy)

	if ipv4:
		return (True,(addr,cidr))
	else: 
		if b < a: sys.exit(("Wrong integer range format (for [a,b], b must be greater than a): " + field_copy))
		#if a < 0 or a > ?? or b < 0 or b > ??: sys.exit("Integer field outside of range listed in config file: " + field_copy)
		return (False,(a,b))


# Function: check_fw_valid_single(discard_slice, firewall, config)
# --- Arguments: discard_slice = input from user, discard_slice CSV filename,
#				firewall = input from user, firewall CSV filename,
#				config = parsed config file from user
# --- Return: Nothing
# --- Purpose: Ensure the discard_slice and firewall files from user are valid CSVs, containing
#				a proper discard slice and firewall
#
def check_fw_valid_single(discard_slice, firewall, config):
	# load rules from input file
	with open(discard_slice, "r") as fd:
		ds_rules = fd.read().splitlines()
	with open(firewall, "r") as fd:
		fw_rules = fd.read().splitlines()

	# ensure valid csv
	if len(ds_rules) == 0 or len(fw_rules) == 0:
		sys.exit("CSV ERR: Given empty file as input")
	csv1, csv2 = [rule.count(",") for rule in ds_rules], [rule.count(",") for rule in fw_rules]
	it1, it2 = groupby(csv1), groupby(csv2)
	if not next(it1,True) and not next(it1,False):
		sys.exit("CSV ERR: Discard slice input not of valid CSV format")
	if not next(it2,True) and not next(it2,False):
		sys.exit("CSV ERR: Firewall input not of valid CSV format")

	# ensure # fields in DS = # fields in FW = # fields in config
	if not len(ds_rules[0].split(",")) == len(fw_rules[0].split(",")):
		sys.exit("CSV ERR: Mismatch in number of fields between discard slice and firewall inputs")
	elif not len(ds_rules[0].split(",")) == len(config):
		sys.exit("CSV ERR: Mismatch in number of fields of discard slice / firewall input and number of entries in config")

	# validate discard slice input
	for i in range(len(ds_rules)):
		rule = ds_rules[i]
		rule_csv = rule.split(",")
		for conf_idx in range(len(config)):
			field = rule_csv[conf_idx]
			conf = config[str(conf_idx)]
			if conf["type"] == "decision":
				if field != "allow" and field != "deny":
					sys.exit("DISCARD SLICE ERR: Decisions can only be allow/deny")
				elif i != len(ds_rules)-1 and field == "deny":
					sys.exit("DISCARD SLICE ERR: Discard slice must be in default-deny format (all rules=allow, last rule=deny)")
				elif i == len(ds_rules)-1 and field != "deny":
					sys.exit("DISCARD SLICE ERR: Final rule in discard slice must be 'deny'")

	# validate firewall input
	for rule in fw_rules:
		rule_csv = rule.split(",")
		for conf_idx in range(len(config)):
			field = rule_csv[conf_idx]
			conf = config[str(conf_idx)]
			if conf["type"] == "decision":
				if field != "allow" and field != "deny":
					sys.exit("FIREWALL ERR: Decisions can only be allow/deny")

	return


# Function: check_config_valid(config_fn)
# --- Arguments: config_fn = filename for input configuration file
# --- Return: dictionary of elements from JSON filename given, otherwise throw error
# --- Purpose: To check and parse input configuration file
#
def check_config_valid(config_fn):
	try:
		with open(config_fn, "r") as fd:
			config = json.load(fd)
			if len(config) == 0:
				sys.exit("CONFIG ERR: Config file must not be empty")

	except:
		sys.exit("CONFIG ERR: Error parsing config file")

	has_decision = False
	for i in range(len(config)):
		conf = config[str(i)]
		if "description" not in conf or "varname" not in conf or "type" not in conf:
			sys.exit("CONFIG ERR: Each field must have a 'varname', 'description' and 'type' attribute")
		if len(conf["varname"]) > 6:
			sys.exit("CONFIG ERR: Ensure varnames in config file have len(varname) <= 6")

		if conf["type"] == "int_range":
			if "min" not in conf or "max" not in conf:
				sys.exit("CONFIG ERR: Fields with 'int_range' type must have 'min' and 'max' attributes")
				try: a,b = int(conf["min"]), int(conf["max"])
				except: sys.exit("CONFIG ERR: Fields with 'int_range' must have integer 'min' and 'max' attributes")
			elif conf["min"] < 0 or conf["max"] < 0:
				sys.exit("CONFIG ERR: Fields with 'int_range' type must not have min or max values < 0")
			elif conf["min"] >= conf["max"]:
				sys.exit("CONFIG ERR: Fields with 'int_range' type must not have min values >= max values")
		elif conf["type"] == "decision" and i == len(config)-1:
			has_decision = True
		elif conf["type"] != "ipv4":
			sys.exit("CONFIG ERR: 'type' attribute must either be 'ipv4', 'int_range', or 'decision'")

	varnames = [config[i]["varname"] for i in config]
	if len(set(varnames)) != len(config):
		sys.exit("CONFIG ERR: Varnames within config file must be unique")

	return config


# Function: parse_args()
# --- Arguments: None
# --- Return: Command line arguments via Namespace object
# --- Purpose: Provide interface for Verifire's command line usage; Process cmd args
#
def argp():
	# Init parser
	parser = argparse.ArgumentParser(
		prog='verifire.py',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description=textwrap.dedent('''\
			Verifire: Formal Firewall Discard Verification Testing

			Definitions:
			- "Firewall policy": A csv file following the format of given config.json file
			- "Discard-slice": A firewall with all allow rules, but the last rule is a deny rule
			- "Complete" firewall / discard slice: Last rule matches every packet (i.e. an allow-all/deny-all rule)
		'''))

	# general arguments - , config
	parser.add_argument('config', help='Configuration file for running FV-D verification', metavar='config.json')

	# verify arguments - verify-rule=filename, verify-policy={filename,directory}
	parser.add_argument('slice', help='CSV file for discard slice', metavar='slice.csv')
	parser.add_argument('fw', help='CSV file for firewall policy', metavar="firewall.csv")

	# Parse & return args
	args = parser.parse_args()
	return args


# Function: main()
# --- Arguments: Takes none, although produces cmd arguments via argparse
# --- Return: None
# --- Purpose: Process cmd arguments & based on args, direct execution path towards other functions
#
def main():
	args = argp()
	print("Validating configuration file...")
	config = check_config_valid(args.config)

	if verify_check(args.slice, args.fw):
		print("Validating input slice and firewall file formats...")
		check_fw_valid_single(args.slice, args.fw, config)

		print("Done! Starting verification process (field validation will be done in real-time)...\n")
		run_verify(args.slice, args.fw, config) 

	return

if __name__ == "__main__":
	main()