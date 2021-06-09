# Verifire

## Introduction

### Description
_Note: This is a term project for a college course._ 

_Verifire_ is a series of Python3 scripts which allow users to verify whether all packets denied by a complete discard slice are also denied by a given complete default-deny firewall policy. To accomplish this, _verifire_ utilizes the _pysmt_ pip module to convert discard slice and firewall policy instances (in the form of a CSV file), into a boolean formula. If a network packet, converted into series of boolean variables, is accepted by a discard slice or firewall policy, then the boolean formula representing that policy will be satisfiable. Otherwise, the formula will not be satisfiable. In order to ensure all packets denied by a discard slice are also denied by a firewall, _verifire_ will convert a discard slice and firewall policy into a boolean formula which is unsatisfiable if this implicative relationship exists, and satisfiable if there exists a packet which is denied by the discard slice, but allowed by the firewall policy. If the boolean formula is satisfiable, then a network packet (in the form of a string) will be printed to the screen which disproves the discard implication relationship. 

### Definitions
* A _firewall rule_ is a series of integer or IPv4 ranges. If a packet's network header information matches all fields in a given firewall rule, then the packet is said to match that rule.
* An _allow-rule_ is a firewall rule where matching packets are allowed by the firewall to enter a network.
* A _deny-rule_ is a firewall rule where matching packets are not allowed, or denied entry to a network. 
* A _firewall policy_ is a CSV file which contains a series of firewall rules.
* A _discard slice_ is a firewall policy, where all rules except for the last one are allow-rules, and the final rule is a deny-rule.
* A _complete policy_ is a firewall policy where the last rule matches all packets.
* A _default-deny policy_ is a complete policy, where the last rule is a deny-rule.

## Usage

### Step 0: Install dependencies
These series of scripts has been tested using Python version 3.8.5 on Ubuntu Linux 20.04, so executing the following commands in other environments is not guaranteed to work. In order to execute the `verifire.py` script, you need to install _pysmt_ and _numpy_ into your environment, and then select a SMT solver. These scripts were tested using the Z3 solver, so installing the Z3 solver in conjunction with _pysmt_ is recommended. You can create a Python3 virtual environment, install the dependencies, and install the Z3 solver using the following commands:
```
# Install, build and activate python3 virtual environment
$ python3 -m pip install --user virtualenv
$ python3 -m venv env
$ source ./env/bin/activate

# Install numpy and pysmt, as well as pysmt Z3 solver
$ pip install numpy pysmt
$ pysmt-install --z3

# Later, when you wish to finish testing and exit the virtual environment
$ deactivate
```

Additionally to create test cases for _verifire_, the firewall generation tool _classbench-ng_ is used. From this we are able to generate firewalls with tens, hundreds, thousands, or even tens of thousands of rules. In order to use _classbench-ng_, it is required that Python3, Ruby 1.9.3+, and RubyGems is installed on your machine. After you have installed these dependencies, you can clone the _classbench-ng_ github repository by running the following command:
```
$ git clone https://github.com/classbench-ng/classbench-ng
```

You can run the following command within the `classbench-ng` directory to ensure that firewall generation is functional, where the output of the following command should produce a tab-deliminated series of 5 firewall rules.
```
$ ./classbench generate v4 vendor/parameter_files/fw1_seed --count=5
```

### Step 1: Understanding how to use _verifire_
There are three filename inputs which are required to run `verifire.py`, as seen from the help page.
```
(env) $ python3 verifire.py -h
usage: verifire.py [-h] config.json slice.csv firewall.csv

Verifire: Formal Firewall Discard Verification Testing

Definitions:
- "Firewall policy": A csv file following the format of given config.json file
- "Discard-slice": A firewall with all allow rules, but the last rule is a deny rule
- "Complete" firewall / discard slice: Last rule matches every packet (i.e. an allow-all/deny-all rule)

positional arguments:
  config.json   Configuration file for running FV-D verification
  slice.csv     CSV file for discard slice
  firewall.csv  CSV file for firewall policy

optional arguments:
  -h, --help    show this help message and exit

```

The three filenames required are `config.json`, `slice.csv`, and `firewall.csv`.

**config.json**: `config.json` must be a valid JSON object which can be read by the Python3 `json` module. Specifically, the dictionary object must be indexed by integers in string format (i.e. indexed by "0", "1", etc. instead of 0, 1, etc.). Each element indexed by these integer strings is another dictionary, which must have `description`, `varname`, and `type` keys. The `description` key is an unbounded string representing the descriptor of a given field which is checked by a firewall. The `varname` key must have a string value where the length of the string is no more than 6 characters. Also keep in mind that no two elements within `config.json` may have the same varname. Finally, the `type` key may have the following values: "int_range", "ipv4", or "decision". If for some element in `config.json` it is true that `type == "int_range"`, then the element must also contain two more values: "min" and "max", which represents the minimum and maximum values possible for an integer in that given field.

The `config.json` file in `verifire/` works with discard slices and firewalls which are generated from the scripts in `verifire/bench2csv/`. However if the user would like to alter the firewalls by adding more fields, changing the format of the firewall rules, etc., then they will also need to alter the `config.json` file which acts as input to the `verifire.py` script.

**slice.csv**: This is the CSV file which represents the discard slice that will be tested against a given firewall policy. Due to the nature of modern-day firewalls, the discard slices found in `verifire/test_cases/`, as well as the ones generated from the scripts in `verifire/bench2csv/` are all complete discard slices (i.e. the final deny-rule matches all packets).

**firewall.csv**: This is the CSV file which represents the firewall policy that will be tested against a given discard slice. Again, due to the nature of modern-day firewalls, the firewall policies found in `verifire/test_cases` and generated by the scripts in `verifire/bench2csv/` are default-deny.

The rules in `slice.csv` and `firewall.csv` must be in accordance with the standard defined in `config.json`. In Steps 2 and 3, it will be shown how you can test the `verifire.py` script against pre-defined test cases generated by _classbench-ng_, and how you can build your own test cases using _classbench-ng_ in conjunction with the scripts found in `verifire/bench2csv/`

### Step 2: Testing _verifire_ using pre-defined test cases
This step will show you how to test `verifire.py` using pre-defined test cases. Moving forward, one important aspect of testing is that the firewall policies which are being tested are very dependent on the discard slices. This is because in order to create a (discard_slice, firewall_policy) tuple that is guaranteed to result in no satisfying assignments for the boolean formula, first a discard slice must be generated, and then the a firewall policy is generated such that each packet denied by the discard slice is guaranteed to be discarded by the generated firewall. The same concept is similar for guaranteeing a (discard_slice, firewall_policy) tuple is guaranteed to result in at least one satisfying assignment for the boolean formula.

With this in mind, there exist two sets of pre-defined test cases in this repository: one for unsatisfying assignments, where each packet denied by the discard slice is denied by the associated firewall policy (found under `verifire/test_cases/unsat/`), and one for satisfying assignments, where there exists a packet denied by the discard slice but allowed by the associated firewall (found under `verifire/test_cases/sat/`).

Within these two directories, there exists the subdirectories `verifire/test_cases/{unsat,sat}/{10,50,100,500,1000}/`, where a given numbered subdirectory represents a discard slice and firewall policy that have (approximately) that many rules. In other words, the discard slices and firewall policies found under the `100/` subdirectory each have 100 rules. Under each numbered directory contain more subdirectories that correspond to a particular test case. Finally, inside of each test case subdirectory is the discard slice and firewall policy files corresponding to that particular test case.

For example, let's you want to test `verifire.py` for a (discard_slice, firewall_policy) tuple that results in an unsatisfying assignment, where the slice and policy both have around 100 rules. You can find the first test case under `verifire/test_cases/unsat/100/test0/`, where this directory will contain the associated `slice_100_0.csv` and `policy_100_0.csv` files, which acts as input to `verifire.py` (the same directory structure also follows for the `verifire/test_cases/sat/` subdirectory). 

To perform this test from the root directory `verifire/`, you can run the following command and observe a similar output.
```
$ python3 verifire.py config.json test_cases/unsat/100/test0/slice_100_0.csv test_cases/unsat/100/test0/policy_100_0.csv

Validating configuration file...
Validating input slice and firewall file formats...
Done! Starting verification process (field validation will be done in real-time)...

- Inputs:
-- Discard slice: verifire/test_cases/unsat/100/test0/slice_100_0.csv
-- Firewall policy: verifire/test_cases/unsat/100/test0/policy_100_0.csv
- Output:
-- Verification succeeded: all packets denied by discard slice are also denied by FW policy
- Statistics:
-- Time to create formula: 9.299233675003052s
-- Time to check satisfiability (verify formula): 0.05014443397521973s


```

### Step 3: Testing _verifire_ using generated test cases
In order to build your own test cases, you will need to download the _classbench-ng_ repository and its associated dependencies as outlined in Step 0. Once this is completed, the assumption is that you have both the `classbench-ng/` and `verifire/` repositories in your current working directory. Moving forward, building your own test cases will involve utilizing the scripts found in `verifire/bench2csv/`. Recall that in order to build a satisfiable/unsatisfiable firewall policy, you will need to provide a discard slice as input. The details of this process is explained below.

In order to build a complete discard slice, you will first need to enter the `classbench-ng` directory. After this, you can perform the following command to output a complete discard slice to `slice.csv` in the parent directory of `classbench-ng/`
```
$ ./classbench generate v4 vendor/parameter_files/fw1_seed --count=100 | python3 ../verifire/bench2csv/bench2csv_slice.py ../verifire/config.json >> ../slice.csv
```

This command will execute the `classbench` binary and generate a firewall policy with 100 rules. Although 100 rules was used in the above command, you can edit out `100` with however many rules you would like to generate. This output is piped into the python3 script `../verifire/bench2csv/bench2csv_slice.py`, which takes a configuration file as input (the same `config.json` entered as input to `verifire.py`). This will create a complete discard slice, which will be output to the parent directory as `slice.csv`.

Now, to build an associated firewall policy, you need to decide if you would like the resulting boolean formula to be unsatisfiable, or to be satisfiable. If your choice is unsatisfiable, then you will need to use the `verifire/bench2csv/bench2csv_unsat.py` script. If your choice is satisfiable, then you will need to use the `verifire/bench2csv_sat.py` script. Both of these scripts take only a discard slice as input (specifically, the discard slice that was generated by the previous command).

To build the firewall policy, you can run the following script, where your `slice.csv` is in your current working directory. The resulting firewall policy will be approximately the same size as the input slice with respect to the number of rules. 
```
$ python3 verifire/bench2csv/bench2csv_unsat.py slice.csv >> policy.csv
```

Now, in your current working directory, you should have both `slice.csv` and the associated `policy.csv`. In order to test the (`slice.csv`, `policy.csv`) tuple to ensure every packet denied by `slice.csv` is also denied by `policy.csv` (or if there exists a packet denied by `slice.csv` that is allowed by `policy.csv`), you can run the following command. It's assumed that `slice.csv`, `policy.csv`, and `verifire/` are in your current working directory.

```
$ python3 verifire/verifire.py verifire/config.json slice.csv policy.csv
```