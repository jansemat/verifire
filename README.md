# Verifire
_Note: This is a term project for a college course._ 

_Verifire_ is a series of Python3 scripts which allow users to verify whether all packets denied by a complete discard slice are also denied by a given complete default-deny firewall policy. To accomplish this, _Verifire_ utilizes the _pysmt_ pip module to convert discard slice and firewall policy instances (in the form of a CSV file), into a boolean formula. If a network packet, converted to binary, is accepted by a discard slice or firewall policy, then the boolean formula will be satisfiable. Otherwise, the formula will not be satisfiable. 



### Definitions



## Usage

### Step 0: Install dependencies


### Step 1:  
