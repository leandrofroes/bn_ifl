from binaryninja import BinaryView
from binaryninja.function import Function

def is_hex_str(s):
    if s[:2] == "0x":
        s = s[2:]

    hex_digits = set("0123456789abcdefABCDEF")

    for val in s:
        if not (val in hex_digits):
            return False
        
    return True

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