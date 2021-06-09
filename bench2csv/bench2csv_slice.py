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
	if len(sys.argv) != 4:
		sys.exit("Usage: python3 " + sys.argv[0] + " [config.json] [big_ruleset.csv] [integer > 0] >> discard_slice.csv")

	# ensure proper config, and that default-deny rule can be made
	try:
		with open(sys.argv[1], "r") as fd:
			config = json.load(fd)
		with open(sys.argv[2], "r") as fd:
			big_rules = fd.read().splitlines()
		num_rules = int(sys.argv[3])
		if num_rules < 0:
			sys.exit("Integer must be >= 0")
	except:
		sys.exit("Error opening config.json or big_ruleset.csv")
	try:
		last_rule = default_deny_rule(config)
	except:
		sys.exit("Can't generate default-deny rule given configuration file")
	
	idx = random.sample([i for i in range(len(big_rules))], num_rules)
	for i in idx:
		print(big_rules[i])
	print(last_rule)
	


if __name__ == "__main__":
	main()
