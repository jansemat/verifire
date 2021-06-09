import sys
import json
import random

# Function: default_deny_rule(config)
# --- Arguments: config = JSON object representing the input firewall fields
# --- Return: the default deny rule which is in line with the config object
# --- Purpose: create and return a default-deny rule with respect to the config object
#
def default_deny_rule(config):
	rule = []
	for i in config:
		if config[i]["type"] == "ipv4":
			rule += ["0.0.0.0/0"]
		elif config[i]["type"] == "int_range":
			mi, ma = config[i]["min"], config[i]["max"]
			rule += [(str(mi) + "-" + str(ma))]
		elif config[i]["type"] == "decision":
			rule += ["deny"]
	return ','.join(rule)

# Function: main()
# --- Arguments: none; takes config.json as command line argument
# --- Return: none
# --- Purpose: takes classbench-ng firewall as stdin, prints out CSV default-deny format
#
def main():
	# ensure proper arguments
	if len(sys.argv) != 2:
		print("Usage: ./classbench [...] | python3 " + sys.argv[0] + " config.json >> discard_slice.csv")
		sys.exit(1)

	# ensure proper config, and that default-deny rule can be made
	try:
		with open(sys.argv[1], "r") as fd:
			config = json.load(fd)
	except:
		sys.exit("Not valid config.json file")
	try:
		last_rule = default_deny_rule(config)
	except:
		sys.exit("Can't generate default-deny rule given configuration file")

	# get input from classbench, turn to CSV
	stdinput = sys.stdin.read().splitlines()
	for i in range(len(stdinput)):
		# turn to CSV
		line = stdinput[i]
		out_data = ' '.join(line.split()).replace(" : ", "-").replace(" ",",").replace("@","") + ",allow"

		# If ip_addrs are 0.0.0.0/0 and 0.0.0.0/0, then replace one of them with other range
		if out_data.split(",")[0] == "0.0.0.0/0" and out_data.split(",")[1] == "0.0.0.0/0":
			idx = random.randint(0,1)
			out_data2 = out_data.split(",")
			out_data2[idx] = ".".join([str(random.randint(0,254)) for i in range(3)]) + ".0/24"
			out_data = ",".join(out_data2)

		# print data and return
		print(out_data)
	print(last_rule)
	return


if __name__ == "__main__":
	main()