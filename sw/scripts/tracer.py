
# Copyright 2021 ETH Zurich
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
from functools import lru_cache

TRACE_IN_REGEX = r'(\d+)\s+(\d+)\s+(\d+)\s+(0x[0-9A-Fa-fz]+)\s+([^#;]*)(\s*#;\s*(.*))?'
FNAME_IN_REGEX = r'........ [<].*[>][:]'
OP_TYPES = ["None", "Reg", "IImmediate", "UImmediate", "JImmediate", "SImmediate", "SFImmediate", "PC", "CSR", "CSRImmmediate", "RegRd", "RegRs2"]
REG_NAMES = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"]
disasm_map = {}
disasm_map_fun = {}
map_fun_id= {}
pending_loads = []
acc_rd_index = {}
debug_en = False
json = False
elf = ""

@lru_cache(maxsize=1024)
def addr2line_cache(addr):
    cmd = f'addr2line -e {elf} -f -a -i {addr}'
    cmd_out = os.popen(cmd).read().split('\n')[2]
    return cmd_out


class CoreInstruction:
    def __init__(self, cyc, time):
        self.duration = -1
        self.stall = True
        self.traceline = None
        self.rd_data = -1
        self.src_line = ""
        self.start_time = time
        self.start_cyc = cyc

    def setup(self, traceline):
        self.traceline = traceline
        self.rd_data = traceline.get_writeback()
        self.src_line = addr2line_cache(traceline.get_pc())

    def set_stall(self, stall): self.stall = stall
    def is_stalled(self): return self.stall
    def set_end_cyc(self, cyc): 
        #print("start_cyc: %i end_cyc: %i" %(self.start_cyc, cyc))
        self.duration = cyc - self.start_cyc

    def set_dest_rd(self, rd, data):
        if (not self.traceline.uses_rd() or not self.traceline.get_rd() == rd):
            print("Error: trying to set RD(0x%x) on this instruction:" % (rd))
            print(self.traceline.line_raw)
            assert False
        self.rd_data = data

    def get_op_str(self, opnum):
        op_type_selector = ["opa_select", "opb_select"]
        op_value_selector = ["opa", "opb"]
        op_rs_selector = ["rs1", "rs2"]

        op_type = OP_TYPES[self.traceline.instr_extras[op_type_selector[opnum]]]
        if (op_type == "None"): return False, ""

        op_value = self.traceline.instr_extras[op_value_selector[opnum]]
        op_reg = "NONE"

        is_reg = True
        if op_type == "Reg" : op_reg = REG_NAMES[self.traceline.instr_extras[op_rs_selector[opnum]]]
        elif op_type == "RegRd" : op_reg = REG_NAMES[self.traceline.instr_extras["rd"]]
        else: is_reg = False

        res_str = op_type
        if (is_reg) : res_str += ":" + op_reg
        res_str += "(0x%lx)" % (op_value)

        return True, res_str

    def print(self, json=False): self.print_json() if json else self.print_txt()

    def get_suffix(self):
        suffix = ""
        has_op_a, op_a_str = self.get_op_str(0)
        if (has_op_a): suffix += " " + op_a_str

        has_op_b, op_b_str = self.get_op_str(1)
        if (has_op_b): suffix += " " + op_b_str

        if (self.traceline.uses_rd()):
            rd_name = REG_NAMES[self.traceline.get_rd()]
            suffix += " RD:%s(0x%lx)" % (rd_name, self.rd_data)

        if (self.traceline.is_load() or self.traceline.is_store()):
            alu_result = self.traceline.get_alu_result()
            suffix += " VA:0x%lx" % (alu_result)

        return suffix

    def print_txt(self):
        fname = disasm_map_fun[self.traceline.get_pc()]        
        instr = disasm_map[self.traceline.get_pc()]
        instr_txt = "%i %i %i %i %i %s %s %s %s " % (\
                        self.start_time, \
                        self.start_cyc, \
                        self.duration, \
                        self.traceline.cluster_id, \
                        self.traceline.core_id, \
                        self.traceline.get_pc(), \
                        self.src_line, \
                        fname, \
                        instr)
        instr_txt += self.get_suffix()
        print(instr_txt)

    def print_json(self):
        fname = disasm_map_fun[self.traceline.get_pc()]        
        #pid = "core_%i_%i" % (self.traceline.cluster_id, self.traceline.core_id)
        pid = self.traceline.trace_id
        tid = map_fun_id[fname]
        json_template = "{\"name\": \"%s\", \"cat\": \"%s\", \"ph\": \"X\", \"ts\": %i, \"dur\": %i, \"pid\": %s, \"tid\": %s, \"args\": {%s}},"
        instr = disasm_map[self.traceline.get_pc()]
        instr_short = instr.split(" ")[0]
        full_instr = instr + self.get_suffix()
        args = "\"pc\": \"%s\", \"instr\": \"%s\", \"cycle\": \"%i\", \"origin\": \"%s\"" % (self.traceline.get_pc(), full_instr, self.start_cyc, self.src_line)
        json_txt = json_template % (instr_short, instr_short, self.start_time, self.duration * 1000, pid, tid, args)
        print(json_txt)


class TraceLine:
    def __init__(self, trace_id, cluster_id, core_id, line: str):
        match = re.search(TRACE_IN_REGEX, line.strip('\n'))
        if match is None:
            raise ValueError('Not a valid trace line:\n{}'.format(line))
        self.time_str, self.cycle_str, self.priv_lvl, self.pc_str, self.insn, _, extras_str = match.groups()        
        self.instr_extras = parse_annotation(extras_str)
        self.cluster_id = int(cluster_id)
        self.core_id = int(core_id)
        self.line_raw = line
        self.trace_id = trace_id

    def is_stall(self): return int(self.instr_extras["stall"])
    def is_load(self): return int(self.instr_extras["is_load"])
    def is_store(self): return int(self.instr_extras["is_store"])
    def is_load_retire(self): return int(self.instr_extras["retire_load"])
    def is_acc(self): return int(self.instr_extras["acc_qvalid"])
    def acc_uses_rd(self): return int(self.instr_extras["acc_uses_rd"])
    def is_acc_retire(self): return int(self.instr_extras["retire_acc"])
    def get_source(self): return int(self.instr_extras["source"])
    def get_time(self): return int(self.time_str)
    def get_pc(self): return self.pc_str
    def get_next_pc(self): return ("0x%x" % (self.instr_extras["pc_d"]))
    def get_cycle(self): return int(self.cycle_str)
    def is_acc_async(self): return self.is_acc() and self.acc_uses_rd()
    def uses_rd(self): return int(self.instr_extras["uses_rd"])
    def get_rd(self): return int(self.instr_extras["rd"])
    def get_lsu_rd(self): return int(self.instr_extras["lsu_rd"])
    def get_ld_result_32(self): return int(self.instr_extras["ld_result_32"])
    def get_writeback(self): return int(self.instr_extras["writeback"])
    def get_alu_result(self): return int(self.instr_extras["alu_result"])
    def get_acc_pid(self): return int(self.instr_extras["acc_pid"])
    def get_acc_pdata_32(self): return int(self.instr_extras["acc_pdata_32"])
    def is_core_instr(self): return  self.get_source() == 0
    def is_valid_core_instr(self): return self.insn.strip() != "DASM(00000000)"

    def print(self):
        print(self.line_raw)


def parse_annotation(dict_str: str):
	return {
		key: int(val, 16)
		for key, val in re.findall(r"'([^']+)'\s*:\s*([^\s,]+)", dict_str)
	}

def dprint(str):
    if (debug_en): print(str)

def record_instr(instr):
    instr.print(json)

def parse_file(trace_id: int, filename: str, exename: str, json: bool):
    f = open(filename, 'r')
    cluster_core_id = filename.split("_")[2].split(".")[0]
    core_id = str(int(cluster_core_id[len(cluster_core_id) - 4: len(cluster_core_id)], 16))
    cluster_id = str(int(cluster_core_id[0:len(cluster_core_id) - 4], 16))
    lines = f.readlines()
    trace_name = os.path.basename(filename)

    current_instr = None
    for line in lines: 
        dprint("\nNew line:")
        dprint(line.strip())

        trace_line = TraceLine(trace_id, cluster_id, core_id, line)
    
        if (trace_line.is_core_instr()):

            # handle retiring of loads
            # We assume that an offloaded instruction cannot be retired in the same cycle it is issued
            if (trace_line.is_load_retire()):
                assert pending_loads
                load_instr = pending_loads.pop(0)
                dprint("load completed (pending loads: %i)!" % (len(pending_loads)))

                # update the RD value (i.e., the value that has been read)
                load_instr.set_dest_rd(trace_line.get_lsu_rd(), trace_line.get_ld_result_32())

                # not the load completed, let's print it
                load_instr.set_end_cyc(trace_line.get_cycle())
                record_instr(load_instr)

            # handle retiring of acc instrs
            if (trace_line.is_acc_retire()):
                dprint("acc completed (rd: 0x%x)" % (trace_line.get_acc_pid()))
                acc_instr = acc_rd_index[trace_line.get_acc_pid()]

                # update the RD value (i.e., the value that has been written back by the acc)
                acc_instr.set_dest_rd(trace_line.get_acc_pid(), trace_line.get_acc_pdata_32())

                # not the acc instruction completed, let's print it
                acc_instr.set_end_cyc(trace_line.get_cycle())
                record_instr(acc_instr)

                # free RD reservation
                del acc_rd_index[trace_line.get_acc_pid()]


            # if pc_q != pc_d --> a new instruction starts at the next cycle
            pc_change = trace_line.get_pc() != trace_line.get_next_pc()

            if (current_instr == None): 
                new_instr_start_cyc = trace_line.get_cycle()
                new_instr_start_time = trace_line.get_time()
                instr = CoreInstruction(new_instr_start_cyc, new_instr_start_time)
                current_instr = instr

            # As soon as the instruction is not stalled, the traceline is valid and we can "initialize" the instruction
            # we are sure that there is a current_instr at this point.
            if (not trace_line.is_stall()):
                dprint("setup instr!")
                is_acc = trace_line.is_acc_async() # this means that the instruction is offloaded to an acc AND we want a response in RD from that
                is_load = trace_line.is_load() # also loads are async
                current_instr.setup(trace_line)
                current_instr.set_stall(False)
                if is_load:
                    # we assume loads are completed in order (FIFO)
                    dprint("new load!")
                    pending_loads.append(instr)
                elif is_acc:
                    dprint("new acc (rd: 0x%x)" % instr.traceline.get_rd())
                    # we don't make any assumption on acc instructions. Just index them by RD (could do the same for loads actually)
                    assert not instr.traceline.get_rd() in acc_rd_index
                    acc_rd_index[instr.traceline.get_rd()] = instr

                # if there is a current instruction that is not stalled and not offloaded (lsu or acc), then at this line we can compute its duration.
                # If it's stalled, then we keep going and wait until it's not stalled anymore
                # If its offloaded (lsu or async) then the termination cannot be determined here but it will be signaled by the offloaded unit
                if (pc_change and not (current_instr.traceline.is_load() or current_instr.traceline.is_acc_async())):
                    end_cycle = trace_line.get_cycle() + 1
                    current_instr.set_end_cyc(end_cycle)
                    record_instr(current_instr)
                    current_instr = None

            # if the PC changes in the next cycle, then move to the next instruction
            if (pc_change):
                dprint("new instr starts (PC: %s -> %s)" % (trace_line.get_pc(), trace_line.get_next_pc()))
                new_instr_start_cyc = trace_line.get_cycle() + 1
                new_instr_start_time = trace_line.get_time() + 1000
                instr = CoreInstruction(new_instr_start_cyc, new_instr_start_time)
                current_instr = instr
                

def load_disasm(filename : str):
    f = open(filename, 'r')
    lines = f.readlines()
    last_fun = ""
    fun_id =0 
    for line in lines:
        match_fname = re.search(FNAME_IN_REGEX, line.strip('\n'))
        if match_fname is not None:
            last_fun = match_fname.group(0).split(" ")[1].split("<")[1].split(">")[0]
            if (last_fun not in map_fun_id):
                map_fun_id[last_fun] = fun_id
                fun_id += 1

        if len(line) > 8 and line[8] == ":":            
            clean = ' '.join(line.split())
            fields = clean.split(' ', 2)
            disasm_map["0x"+fields[0].split(':')[0]] = fields[2]
            disasm_map_fun["0x"+fields[0].split(':')[0]] = last_fun
    f.close()

def main():
    global elf, json, debug_en
    parser = argparse.ArgumentParser(description='Converts the Snitch traces into .txt traces or .json traces (that can be visualized in Google chrome).', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # Mandatory arguments
    parser.add_argument('-d', '--disasm', help='The disasm.', required=True)
    parser.add_argument('-e', '--exe', help='The executable.', required=True)
    parser.add_argument('-x', '--text', help='Converts to .txt. If not specified, it converts to .json.', required=False, action='store_true')
    parser.add_argument('-b', '--debug', help='Enable debug', required=False, action='store_true')
    parser.add_argument('traces', nargs='*')

    args = parser.parse_args()
    json = not args.text
    elf = args.exe
    traces = args.traces
    load_disasm(args.disasm)
    debug_en = args.debug
    trace_id = 0

    # core: {"pid":59843,"tid":59843,"ts":0,"ph":"M","cat":"__metadata","name":"process_name","args":{"name":"core_0_0"}},
    # fun {"pid":59843,"tid":59843,"ts":0,"ph":"M","cat":"__metadata","name":"thread_name","args":{"name":"foo"}},
    json_core_metadata_template = "{\"pid\":%i,\"tid\":0,\"ts\":0,\"ph\":\"M\",\"cat\":\"__metadata\",\"name\":\"process_name\",\"args\":{\"name\":\"%s\"}},"
    json_fun_metadata_template = "{\"pid\":%i,\"tid\":%i,\"ts\":0,\"ph\":\"M\",\"cat\":\"__metadata\",\"name\":\"thread_name\",\"args\":{\"name\":\"%s\"}},"

    if (json): # prolog and metadata
        print('{"traceEvents": [')

    for trace in traces:
        if (json):
            print(json_core_metadata_template % (trace_id, os.path.basename(trace)))

            for fun in map_fun_id.items():
                print(json_fun_metadata_template % (trace_id, fun[1], fun[0]))

        parse_file(trace_id, trace, args.exe, json)
        trace_id += 1

    if (json): print("{}]}\n") # epilog

if __name__== "__main__":
	main()
