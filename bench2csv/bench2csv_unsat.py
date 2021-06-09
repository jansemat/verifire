import sys
import random
import math

# Function: main()
# --- Arguments: none; takes slice.csv as command line argument
# --- Return: none
# --- Purpose: takes slice.csv discard slice as argument, prints out UNSAT firewall policy (default-deny format)
#
def main():
	# ensure proper arguments
	if len(sys.argv) != 2:
		print("Usage: python3 " + sys.argv[0] + " discard_rule.csv >> unsat_fw_policy.csv")
		sys.exit(1)

	# ensure slice.csv can be read
	try:
		with open(sys.argv[1], "r") as fd:
			ds_rules = fd.read().splitlines()
	except:
		sys.exit("Couldn't open " + sys.argv[1])

	# turn some of slice.csv rules to deny-rules, to create UNSAT firewall
	acc_rules, deny_rule = ds_rules[:-1], ds_rules[-1]
	ten_percent = math.ceil(0.1 * len(ds_rules))
	if len(acc_rules) > 0:
		idx = random.sample([i for i in range(len(acc_rules))], ten_percent)
		for i in idx:
			acc_rules[i] = ','.join(acc_rules[i].split(",")[:-1]) + ",deny"

	# print UNSAT firewall policy
	for rule in acc_rules: print(rule)
	print(deny_rule)


if __name__ == "__main__":
	main()