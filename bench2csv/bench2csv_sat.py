import sys
import math
import random


# Function: main()
# --- Arguments: none; takes slice.csv as command line argument
# --- Return: none
# --- Purpose: takes slice.csv discard slice as argument, prints out SAT firewall policy (default-deny format)
#
def main():
	# ensure proper arguments
	if len(sys.argv) != 2:
		print("Usage: python3 " + sys.argv[0] + " discard_slice.csv >> sat_fw.csv")
		sys.exit(1)

	# ensure slice.csv can be read
	try:
		with open(sys.argv[1], "r") as fd:
			ds_rules = fd.read().splitlines()
	except:
		sys.exit("Couldn't open " + sys.argv[1])

	# create accepting rules that are denied by slice
	acc_rules, deny_rule = ds_rules[:-1], ds_rules[-1]

	if len(acc_rules) == 0:
		sys.exit("Can't create SAT firewall policy for discard slice with only a default-deny rule. Will always be UNSAT.")

	ten_percent = math.ceil(0.1 * len(ds_rules))
	idx = random.sample([i for i in range(len(acc_rules))], ten_percent)
	for i in idx:
		acc_rules[i] = ','.join(acc_rules[i].split(",")[:-1]) + ",deny"

	if len(acc_rules) >= 4:
		# add accepting rules to original slice rules, to create SAT firewall
		acc_all_idx = random.sample([i for i in range(len(acc_rules))], 4)
		acc_all_strs = []
		for i in range(4):
			acc_all_str = deny_rule.split(",")[:-1]
			acc_all_str[0] = str(64*i) + ".0.0.0/2"
			acc_all_str = ','.join(acc_all_str) + ",allow"
			acc_rules.insert(random.randint(0,len(acc_rules)), acc_all_str)

	else:
		for i in range(4):
			acc_all_str = deny_rule.split(",")[:-1]
			acc_all_str[0] = str(64*i) + ".0.0.0/2"
			acc_all_str = ','.join(acc_all_str) + ",allow"
			acc_rules.append(acc_all_str)


	# print SAT firewall policy
	for rule in acc_rules: print(rule)
	print(deny_rule)


if __name__ == "__main__":
	main()