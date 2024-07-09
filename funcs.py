from binaryninja import BinaryView
from binaryninja.function import Function
from binaryninja.enums import InstructionTextTokenType

def get_start(f: Function) -> int:
    """
    Get the function start address.
    :param f: The target function.
    :return: The start address of the target function.
    """
    return f.start

def get_end(f: Function) -> int:
    """
    Get the address of the latest byte of a function.
    :param f: The target function.
    :return: The address of the latest byte of the target function.
    """      
    return f.address_ranges[-1].end - 1

def get_name(bv: BinaryView, addr: int) -> str:
    """
    Get the function symbol name.
    :param bv: The current binary view.
    :param addr: The function address to use to locate the function.
    :return: The function name.
    """
    f = bv.get_function_at(addr)

    if not f:
        return ""
    
    return f.symbol.short_name

def get_type_info(bv: BinaryView, addr: int) -> str:
    """
    Get the function return type and its calling convention.
    :param bv: The current binary view.
    :param addr: The function address to use to locate the function.
    :return: A string with the type info following the format 
    '<return_type> <calling_convention'
    """
    f = bv.get_function_at(addr)

    if not f:
        return ""

    calling_convention = f.calling_convention.name.lstrip("_")
    return_type = f.return_type.get_string()

    if calling_convention == "win64":
        calling_convention = "fastcall"

    return f"{return_type} {calling_convention}"

def get_args(bv: BinaryView, addr: int) -> str:
    """
    Get the function arguments.
    :param bv: The current binary view.
    :param addr: The function address to use to locate the function.
    :return: A string representation of the function parameters
    following the format '(<type> arg1, <type> arg2, ...)'
    """
    f = bv.get_function_at(addr)

    if not f:
        return ""
    
    params_list = []

    params = f.type.parameters
    
    if params:
        for param in params:
            params_list.append(f"{param.type} {param.name}")
    
        s = ", ".join(params_list)

        return f"({s})"

    return "(void)"

def get_basic_blocks_count(bv: BinaryView, addr: int) -> int:
    """
    Get the number of basic blocks within a function.
    :param bv: The current binary view.
    :param addr: The function address to use to locate the function.
    :return: The number of basic blocks of the target function.
    """
    f = bv.get_function_at(addr)

    if not f:
        return 0
    
    return len(f.basic_blocks)

def get_callers_info(f: Function) -> list:
    """
    Get the name of the function callers and the address from 
    where the call is being performed.
    :param f: The target function.
    :return: A list with the caller names and the call locations.
    """
    caller_refs = []

    for caller in f.caller_sites:
        info = {}
        
        info["foreign_val"] = caller.function.name
        info["from_addr"] = caller.address

        caller_refs.append(info)
    
    return caller_refs 

def _is_inside_executable_segment(bv: BinaryView, addr: int) -> bool:
    """
    Check if an address is inside an executable segment or not.
    :param bv: The current binary view
    :param addr: The address to be checked.
    :return: If its executable or not.
    """
    for segment in bv.segments:
        if addr >= segment.start and addr <= segment.end:
            return segment.executable
    
    return False

def _parse_data_token(bv: BinaryView, token: InstructionTextTokenType) -> tuple:
    """
    Parse a data token and determine what type of data we are
    dealing with (e.g. string, function pointer, etc).
    :param bv: The current binary view.
    :param token: The data token itself.
    :return: A tuple containing the token information.
    """
    token_value = token.value

    # Make sure its a valid address
    if bv.is_valid_offset(token_value):
        # Check if its a string
        token_value_str = bv.get_string_at(token_value)
        if token_value_str:
            return token_value_str, "string"
        if _is_inside_executable_segment(bv, token_value):
            token_inst = bv.get_disassembly(token_value)
            if token_inst:
                token_inst = token_inst.replace("     ", " ")
                inst = f"inst ptr -> {token_inst}"
                return inst, "instruction"
        else:
            # Check if its pointing to some other data type
            data = bv.get_data_var_at(token_value)
            if data is not None:
                try:
                    data_value = data.value

                    # If its not an int it might be a function name
                    if not isinstance(data.value, int):
                        if data.name:
                            return data.name, "function"
                        # Otherwise its probably a void pointer
                        elif data_value is None:
                            return "void*", "data"
                    else:
                        # If its an int check if its a function pointer
                        if bv.is_valid_offset(data_value):
                            for f in bv.functions:
                                if data_value == f.start:
                                    func_name = f.symbol.short_name
                                    if func_name:
                                        return func_name, "function"

                        value = ""

                        # Might be just an int so check if its labeled or not
                        if data.name:
                            value = f"{data.name} = {hex(data_value)}"
                        else:
                            value = f"{data.type.get_string()} {hex(data_value)}"

                        return value, "data"
                except:
                    pass

    return None, None

def get_callee_info(bv: BinaryView, f: Function) -> list:
    """
    Get the name, type and value of the callee references.
    :param bv: The current binary view.
    :param f: The target function.
    :return: A list containing the callee refs information.
    """
    callees_refs = []

    for bb in f.basic_blocks:
        disas = bb.get_disassembly_text()
        for inst in disas:
            info = {}

            for token in inst.tokens:
                # Check data tokens
                if token.type == InstructionTextTokenType.DataSymbolToken:
                    value, type = _parse_data_token(bv, token)

                    if value and type:
                        foreign_val = ""

                        # Construct the data format based on
                        # the parsed type results
                        if type == "function":
                            foreign_val = value
                        if type == "string":
                            str_type = value.type
                            str_encoding = value._decodings[str_type]
                            foreign_val = f"[{hex(token.value)}]: {str_encoding} '{value}'"
                        if type == "data" or type == "instruction":
                            foreign_val = f"[{hex(token.value)}]: {value}"

                        info["foreign_val"] = foreign_val
                        info["from_addr"] = inst.address

                        callees_refs.append(info)
                        break
                # Check imported functions
                elif token.type == InstructionTextTokenType.ImportToken:
                    info["foreign_val"] = f"[{hex(token.value)}]: extrn {token.text}"
                    info["from_addr"] = inst.address
                    callees_refs.append(info)
                    break
                # Check local functions
                elif token.type == InstructionTextTokenType.CodeSymbolToken:
                    info["foreign_val"] = token.text
                    info["from_addr"] = inst.address
                    callees_refs.append(info)
                    break
                                    
    return callees_refs

def get_indirect_transfers(f: Function) -> list:
    """
    Get all the indirect transfers (e.g. call rax) in the current
    function.
    :param f: The target function.
    :return: A list containing all the instruction addresses and
    values.
    """
    redirect_inst = ""
    indirect_calls = []

    for block in f.basic_blocks:
        disas = block.get_disassembly_text()
        for inst in disas:
            for i in range(len(inst.tokens) - 2):
                info = {}

                if inst.tokens[i].text == "call":
                    redirect_inst = "call"
                if inst.tokens[i].text == "jmp":
                    redirect_inst = "jmp"

                if redirect_inst:
                    if inst.tokens[i+2].type == InstructionTextTokenType.RegisterToken:
                        info["foreign_val"] = f"{redirect_inst} {inst.tokens[i+2].text}"
                        info["from_addr"] = inst.address
                        indirect_calls.append(info)
                        redirect_inst = ""
                        break

                    redirect_inst = ""

    return indirect_calls


class FunctionInfo:
    """
    Represents the information of a single function.
    """
    def __init__(self,
                 start,
                 end,
                 name,
                 ftype,
                 args,
                 basic_blocks_count,
                 callers_info,
                 callers_refs_count,
                 callee_info,
                 callee_refs_count,
                 indirect_transfers_info,
                 indirect_transfers_count
                 ):
        
        # Functions main info
        self.start = start
        self.end = end
        self.name = name
        self.type = ftype
        self.args = args
        self.basic_blocks_count = basic_blocks_count
        
        # Callers refs
        self.callers_info = callers_info
        self.callers_refs_count = callers_refs_count

        # Callee refs
        self.callee_info = callee_info
        self.callee_refs_count = callee_refs_count

        # Indirect transfers
        self.indirect_transfers_info = indirect_transfers_info
        self.indirect_transfers_count = indirect_transfers_count

class FunctionsInfoMapper:
    """
    Represents a mapper with all the functions info records.
    """
    funcs_info_list = []

    def __init__(self, bv: BinaryView):
        self.bv = bv
        
        self.init_funcs_info_list()

    def init_funcs_info_list(self) -> None:
        """
        Initialize all the functions informations.
        :return None:
        """
        # Reset list
        FunctionsInfoMapper.funcs_info_list = []

        for f in self.bv.functions:
            # Functions main info
            start = get_start(f)
            end = get_end(f)
            name = get_name(self.bv, f.start)
            ftype = get_type_info(self.bv, f.start)
            args = get_args(self.bv, f.start)
            basic_blocks_count = get_basic_blocks_count(self.bv, f.start)
            
            # Callers refs
            callers_info = self._init_callers_info_list(f)
            callers_refs_count = len(callers_info)
    
            # Callee refs
            callee_info = self._init_callee_info_list(self.bv, f)
            callee_refs_count = len(callee_info)

            # Indirect transfers
            indirect_transfers_info = self._init_indirect_transfers_info_list(f)
            indirect_transfers_count = len(indirect_transfers_info)

            # Populate a single function with the proper info
            func_info = FunctionInfo(
                start,
                end,
                name,
                ftype,
                args,
                basic_blocks_count,
                callers_info,
                callers_refs_count,
                callee_info,
                callee_refs_count,
                indirect_transfers_info,
                indirect_transfers_count
            )

            # Append the info to our global list
            FunctionsInfoMapper.funcs_info_list.append(func_info)

    @staticmethod
    def _init_callers_info_list(f: Function) -> list:
        """
        Set the 'refs from' info for a function.
        :param f: The target function.
        :return: A list containing all the callers info of a function.
        """
        callers_info = get_callers_info(f)

        if not callers_info:
            return []

        callers_info_list = []   

        for caller_info in callers_info:
            try:
              info = {}
              info["foreign_val"] = caller_info["foreign_val"]
              info["from_addr"] = hex(caller_info["from_addr"])
              callers_info_list.append(info)
            except KeyError:
                pass
        
        return callers_info_list

    @staticmethod
    def _init_callee_info_list(bv: BinaryView, f: Function) -> list:
        """
        Set the 'refs to' info for a function.
        :param bv: The current binary view.
        :param f: The target function.
        :return: A list containing all the callee info of a function.
        """
        callees_info = get_callee_info(bv, f)

        if not callees_info:
            return []

        callee_info_list = []

        # Set the 'refs to' info for the function
        for callee_info in callees_info:
          try:
            info = {}
            info["foreign_val"] = callee_info["foreign_val"]
            info["from_addr"] = hex(callee_info["from_addr"])
            callee_info_list.append(info)
          except KeyError:
              pass
        
        return callee_info_list

    @staticmethod
    def _init_indirect_transfers_info_list(f: Function) -> list:
        """
        Set the indirect transfers info for the function.
        :param f: The target function.
        :return: A list containing all the indirect transfers info of
        a function.
        """
        indirect_transfers_info = get_indirect_transfers(f)

        if not indirect_transfers_info:
            return []

        indirect_transfers_info_list = []

        # Set the indirect transfers info for the function
        for call_info in indirect_transfers_info:
          try:
            info = {}
            info["foreign_val"] = call_info["foreign_val"]
            info["from_addr"] = hex(call_info["from_addr"])
            indirect_transfers_info_list.append(info)
          except KeyError:
              pass
        
        return indirect_transfers_info_list