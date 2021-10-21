# Copyright 2020 ETH Zurich
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

import re
import sys
import os
import queue
import argparse

TRACE_IN_REGEX = r'(\d+)\s+(\d+)\s+(\d+)\s+(0x[0-9A-Fa-fz]+)\s+([^#;]*)(\s*#;\s*(.*))?'
FNAME_IN_REGEX = r'........ [<].*[>][:]'

OP_TYPES = ["None", "Reg", "IImmediate", "UImmediate", "JImmediate", "SImmediate", "SFImmediate", "PC", "CSR", "CSRImmmediate", "RegRd", "RegRs2"]
REG_NAMES = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"]
disasm_map = {}
disasm_map_fun = {}
durs_idx = {}

def flush_buffer(buffer, exename):
	# Pass all hex addresses to addr2line and read back the results.
	cmd = 'addr2line -e ' + exename
	for s in buffer:
		cmd += ' ' + s
	p = os.popen(cmd)
	lines = p.readlines()
	ret = []
	for line in lines: 
		ret += [line.split("/")[-1].replace("\n", "").replace("(discriminator 1)", "").rstrip()]
	return ret

def parse_annotation(dict_str: str):
	return {
		key: int(val, 16)
		for key, val in re.findall(r"'([^']+)'\s*:\s*([^\s,]+)", dict_str)
	}

def get_dur_and_fnames(filename: str, exename: str):
	f = open(filename, 'r')
	lines = f.readlines()
	prev = 0
	durs = []
	fnames = []
	pc_strs = []
	pending_loads = queue.Queue()
	index = 0
	starts = [None] * len(lines) # When istruction at line i starts
	ends = [None] * len(lines) # When istruction at line i ends
	current_pc = ""
	current_pc_line = 0
	ic_wait = False
	new_instr = True
	for line in lines: 
		match = re.search(TRACE_IN_REGEX, line.strip('\n'))
		if match is None:
			raise ValueError('Not a valid trace line:\n{}'.format(line))
		time_str, cycle_str, priv_lvl, pc_str, insn, _, extras_str = match.groups()
		
		ends[current_pc_line] = int(time_str)

		if pc_str != current_pc:
			starts[index] = int(time_str)
			current_pc = pc_str
			current_pc_line = index
			new_instr = True
		else:
			new_instr = False

		instr_extras = parse_annotation(extras_str)
		stall = instr_extras["stall"]
		is_load = instr_extras["is_load"]
		retire_load = instr_extras["retire_load"]
		rd = instr_extras["rd"]
		lsu_rd = instr_extras["lsu_rd"]
		if is_load == 1 and (new_instr or ic_wait):
			pending_loads.put((index, rd))
			#print("Pushing load " + str(index) + " " + str(rd))
		if retire_load == 1 and lsu_rd != 0:
			old_idx, old_rd = pending_loads.get()
			#print("Popping load " + str(old_idx) + " " + str(old_rd))
			ends[old_idx] = int(time_str)
			if lsu_rd != old_rd:
				print("idx " + str(index) + " rd mismatch " + str(lsu_rd) + " vs. " + str(old_rd))
				exit(-1)
		pc_strs += [pc_str]
		index += 1
		prev = int(time_str)        
		if "00000000" in insn:
			ic_wait = True
		else:
			ic_wait = False

		if(len(pc_strs) == 2000):
			fnames += flush_buffer(pc_strs, exename)
			pc_strs = []        
	fnames += flush_buffer(pc_strs, exename)
	f.close()
	ends[current_pc_line] = int(time_str) + 1000
	return starts, ends, fnames

def get_op_str(opnum, instr_extras):

	op_type_selector = ["opa_select", "opb_select"]
	op_value_selector = ["opa", "opb"]
	op_rs_selector = ["rs1", "rs2"]

	op_type = OP_TYPES[instr_extras[op_type_selector[opnum]]]
	if (op_type == "None"): return False, ""

	op_value = instr_extras[op_value_selector[opnum]]
	op_reg = "NONE"

	is_reg = True
	if op_type == "Reg" : op_reg = REG_NAMES[instr_extras[op_rs_selector[opnum]]]
	elif op_type == "RegRd" : op_reg = REG_NAMES[instr_extras["rd"]]
	else: is_reg = False

	res_str = op_type
	if (is_reg) : res_str += ":" + op_reg
	res_str += "(0x%lx)" % (op_value)

	return True, res_str


# def get_rd_str(instr_extras):
# 	write_rd = instr_extras["write_rd"] == "1"

# 	if (not write_rd) : return False, ""

# 	rd_str = "
# 	if (write_rd) :
		


def parse_file(filename: str, exename: str, json: bool):
	f = open(filename, 'r')
	cluster_core_id = filename.split("_")[2].split(".")[0]
	core_id = str(int(cluster_core_id[len(cluster_core_id) - 4: len(cluster_core_id)], 16))
	cluster_id = str(int(cluster_core_id[0:len(cluster_core_id) - 4], 16))
	starts, ends, fnames = get_dur_and_fnames(filename, exename)
	lines = f.readlines()
	id = 0
	if json:
		print("{\"traceEvents\": [")
	for line in lines: 
		match = re.search(TRACE_IN_REGEX, line.strip('\n'))
		if match is None:
			raise ValueError('Not a valid trace line:\n{}'.format(line))
		time_str, cycle_str, priv_lvl, pc_str, insn, _, extras_str = match.groups()
		instr_extras = parse_annotation(extras_str)
		stall = instr_extras["stall"]
		is_load = instr_extras["is_load"]
		retire_load = instr_extras["retire_load"]

		print("")
		print(instr_extras)
		#key = insn.split("(")[1].split(")")[0]
		key = pc_str
		if starts[id] != None and ends[id] != None:
			duration = str(ends[id] - starts[id])        
			location = fnames[id]
			fname = disasm_map_fun[key]        
			instr = disasm_map[key]
			instr_short = instr.split(" ")[0]
			has_opa, opa_str = get_op_str(0, instr_extras)
			has_opb, opb_str = get_op_str(1, instr_extras)

			if json:
				print("{\"name\": \"" + instr_short + "\", \
						\"cat\": \"" + instr_short + "\", \
						\"ph\": \"X\", \
						\"ts\": " + time_str + ", \
						\"dur\": " + duration + ", \
						\"pid\": \"./trace_core_" + cluster_id + "_" + core_id + ".log\", \
						\"tid\": \"" + fname + "\", \
						\"args\":{\"pc\": \"" + pc_str + "\", \
								  \"instr\": \"" + instr + "\", \
								  \"time\": \"" + cycle_str + "\", \
								  \"Origin\": \" " + location + " \" \
								  }\
					   },")
			else:
				instr_text = "%s %s %s %s %s %s %s %s %s \"%s\" " % (time_str, cycle_str, duration, cluster_id, core_id, fname, pc_str, location, instr_short, instr)

				if has_opa:
					instr_text += "OPA:" + opa_str + " "

				if has_opb:
					instr_text += "OPB:" + opb_str + " "

				print(instr_text)

				# print(	time_str 			+ " " + 
				# 		cycle_str 			+ " " + 
				# 		duration 			+ " " + 
				# 		cluster_id 			+ " " + 
				# 		core_id 			+ " " + 
				# 		fname 				+ " " + 
				# 		pc_str 				+ " " + 
				# 		location 			+ " " + 
				# 		instr_short 		+ " " + 
				# 		"\"" + instr + "\"" + " " + 
				# 		"OPA: " + opa_type + "(" + opa_value + ") " + 
				# 		"OPB: " + opb_type + "(" + opb_value + ") ")
		id += 1
	f.close()
	if json:
		print ("{}]}")

def load_disasm(filename : str):
	f = open(filename, 'r')
	lines = f.readlines()
	last_fun = ""
	for line in lines: 
		match_fname = re.search(FNAME_IN_REGEX, line.strip('\n'))
		if match_fname is not None:
			last_fun = match_fname.group(0).split(" ")[1].split("<")[1].split(">")[0]
		if len(line) > 8 and line[8] == ":":            
			clean = ' '.join(line.split())
			fields = clean.split(' ', 2)
			disasm_map["0x"+fields[0].split(':')[0]] = fields[2]
			disasm_map_fun["0x"+fields[0].split(':')[0]] = last_fun
	f.close()

def main():
	parser = argparse.ArgumentParser(description='Converts the Snitch traces into .txt traces or .json traces (that can be visualized in Google chrome).', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	# Mandatory arguments
	parser.add_argument('-t', '--trace', help='The trace to convert.', required=True)
	parser.add_argument('-d', '--disasm', help='The disasm.', required=True)
	parser.add_argument('-e', '--exe', help='The executable.', required=True)
	parser.add_argument('-x', '--text', help='Converts to .txt. If not specified, it converts to .json.', required=False, action='store_true')
	args = parser.parse_args()
	json = not args.text
	load_disasm(args.disasm)
	parse_file(args.trace, args.exe, json)

if __name__== "__main__":
	main()
