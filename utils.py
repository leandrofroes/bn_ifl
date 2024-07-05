from binaryninja import BinaryView
from binaryninja.function import Function
from binaryninja.enums import InstructionTextTokenType

class FunctionInfo:
    """
    Represent the information of a single function.
    """
    def __init__(self, f: Function, bv: BinaryView):
        self.bv = bv
        self.function = f

        # Functions main info
        self.start = self.function.start
        self.end = self._get_end()
        self.name = self.function.symbol.short_name
        self.type = self._get_type_info()
        self.args = self._get_args()
        self.basic_blocks_count = len(self.function.basic_blocks)
        
        # Callers refs
        self.callers_info = self._get_callers_info()
        self.callers_refs_count = len(self.function.callers)

        # Callee refs
        self.callee_info = self._get_callee_info()
        self.callee_refs_count = len(self.callee_info)

        # Indirect transfers
        self.indirect_transfers_info = self._get_indirect_transfers()
        self.indirect_transfers_count = len(self.indirect_transfers_info)

    def _get_args(self) -> str:
        """
        Get the function arguments.
        :return: A string representation of the function parameters
        following the format '(<type> arg1, <type> arg2, ...)'
        """
        params_list = []

        params = self.function.type.parameters
        
        if params:
            for param in params:
                params_list.append(f"{param.type} {param.name}")
        
            s = ", ".join(params_list)

            return f"({s})"

        return "(void)"

    def _get_type_info(self) -> str:
        """
        Get the function return type and its calling convention.
        :return: A string with the type info following the format 
        '<return_type> <calling_convention'
        """
        calling_convention = self.function.calling_convention.name.lstrip("_")
        return_type = self.function.return_type.get_string()

        if calling_convention == "win64":
            calling_convention = "fastcall"

        return f"{return_type} {calling_convention}"

    def _get_end(self) -> int:
        """
        Get the address of the latest byte of a function.
        :return: The address of the latest byte of the target function.
        """      
        return self.function.address_ranges[-1].end - 1

    def _get_callers_info(self) -> list:
        """
        Get the name of the function callers and the address from 
        where the call is being performed.
        :return: A list with the caller names and the call locations.
        """
        caller_refs = []

        for caller in self.function.caller_sites:
            info = {}
            
            info["foreign_val"] = caller.function.name
            info["from_addr"] = caller.address

            caller_refs.append(info)
        
        return caller_refs 

    def _is_inside_executable_segment(self, addr: int) -> bool:
        """
        Check if an address is inside an executable segment or not.
        :param addr: The address to be checked.
        :return: If its executable or not.
        """
        for segment in self.bv.segments:
            if addr >= segment.start and addr <= segment.end:
                return segment.executable
        
        return False

    def _parse_data_token(self, token: InstructionTextTokenType) -> tuple:
        """
        Parse a data token and determine what type of data we are
        dealing with (e.g. string, function pointer, etc).
        :param token: The data token itself.
        :return: A tuple containing the token information.
        """
        token_value = token.value

        # Make sure its a valid address
        if self.bv.is_valid_offset(token_value):
            # Check if its a string
            token_value_str = self.bv.get_string_at(token_value)
            if token_value_str:
                return token_value_str, "string"
            if self._is_inside_executable_segment(token_value):
                token_inst = self.bv.get_disassembly(token_value)
                if token_inst:
                    token_inst = token_inst.replace("     ", " ")
                    inst = f"inst ptr -> {token_inst}"
                    return inst, "instruction"
            else:
                # Check if its pointing to some other data type
                data = self.bv.get_data_var_at(token_value)
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
                            if self.bv.is_valid_offset(data_value):
                                for f in self.bv.functions:
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

    def _get_callee_info(self) -> list:
        """
        Get the name, type and value of the callee references. 
        :return: A list containing the callee refs information.
        """
        callees_refs = []

        for bb in self.function.basic_blocks:
            disas = bb.get_disassembly_text()
            for inst in disas:
                info = {}

                for token in inst.tokens:
                    # Check data tokens
                    if token.type == InstructionTextTokenType.DataSymbolToken:
                        value, type = self._parse_data_token(token)

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
    
    def _get_indirect_transfers(self) -> list:
        """
        Get all the indirect transfers (e.g. call rax) in the current
        function.
        :return: A list containing all the instruction addresses and
        values.
        """
        redirect_inst = ""
        indirect_calls = []

        for block in self.function.basic_blocks:
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

#--------------------------------------------------------------------------
# File import/export utils
#--------------------------------------------------------------------------

def is_hex_str(s):
    if s[:2] == "0x":
        s = s[2:]

    hex_digits = set("0123456789abcdefABCDEF")

    for val in s:
        if not (val in hex_digits):
            return False
        
    return True

def save_funcs_to_file(bv: BinaryView, filename: str, extension: str) -> None:
    """
    Save the function names and RVA into a file. The supported formats
    are either CSV (default) or TAG (PE-bear, PE-sieve compatibile).
    :param bv: The current binary view.
    :param filename: The name of the file to save the funcs info.
    :param extension: The extension to use.
    :return: None
    """
    func_list = [] 
    delim = ","

    if ".tag" in extension:
        delim = ";"

    for f in bv.functions:
        va = f.start
        image_base = bv.start
        rva = va - image_base
        func_name = f.symbol.short_name
        
        line = "%lx%c%s" % (rva, delim, func_name)
        func_list.append(line)

    with open(filename, 'w') as f:
        for item in func_list:
            f.write("%s\n" % item)

def _strip_import_name(func_name: str) -> str:
    """
    Clean up a function name to only keep the import name and remove
    things like the DLL name and the ordinal.
    :param func_name: The name of the function to be cleaned.
    :result: The import name without the extra info.
    """
    fn1 = func_name.split('.')

    if len(fn1) >= 2:
        func_name = fn1[1].strip()
    fn1 = func_name.split('#')
    if len(fn1) >= 2:
        func_name = fn1[0].strip()

    return func_name

def _define_import_thunk(bv: BinaryView, start: int, thunk_value: int) -> None:
    """
    If the binary has the Import Thunk filled, define it as a data chunk
    of appropriate size.
    :param bv: The current binary view.
    :param start: The function start
    :param thunk_value: The import thunk value.
    :return: None
    """
    data = bv.get_data_var_at(start)
    if data:
        data_value = data.value
        if data_value:
            if data_value == thunk_value:
                bv.define_data_var(start, "void*", None)

def import_funcs_from_file(bv: BinaryView, filename: str, image_base: int) -> tuple:
    """
    Read and parse the functions info from a file. The supported formats
    are either CSV (default) or TAG (PE-bear, PE-sieve compatibile).
    :param bv: The current binary view.
    :param filename: The name of the file to save the funcs info.
    :return: A tuple containing the number of functions and comments
    defined.
    """
    funcs_start_list = [f.start for f in bv.functions]
    delim = ","     # New delimiter (for CSV format)
    delim2 = ":"    # Old delimiter
    rva_index = 0
    func_name_index = 1
    is_imp_list = False

    if ".imports.txt" in filename:
        is_imp_list = True
        func_name_index = 2

    if ".tag" in filename:
        delim2 = ";"

    functions = 0
    comments = 0
    
    with open(filename, "r") as f:
        for line in f.readlines():
            line = line.strip()
            func_entry = line.split(delim)

            if len(func_entry) < 2:
                # Try the old delimiter
                func_entry = line.split(delim2)
            if len(func_entry) < 2:
                continue

            start = 0
            addr_chunk = func_entry[rva_index].strip()

            if not is_hex_str(addr_chunk):
                continue
            try:
                start = int(addr_chunk, 16)
            except ValueError:
                # This line doesn't start from an offset, so skip it
                continue

            func_name = func_entry[func_name_index].strip()

            # Check if its an RVA and if so, convert to VA
            if start < image_base:
                start = image_base + start

            if is_imp_list or (start in funcs_start_list):
                if is_imp_list:
                    func_name = _strip_import_name(func_name)
                    thunk_val = int(func_entry[1].strip(), 16)
                    _define_import_thunk(bv, start, thunk_val)

                # Rename the function
                f = bv.get_function_at(start)
                if isinstance(f, Function):
                    f.name = func_name
                    functions += 1
                continue

            # If we don't have entries for the function we just add
            # a comment
            bv.set_comment_at(start, func_name)
            comments += 1

    return functions, comments