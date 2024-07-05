from binaryninjaui import (
    UIAction, 
    Menu,
    UIActionContext,
    UIActionHandler,
    WidgetPane
)

from binaryninja.binaryview import BinaryView

from . import ui
from . import utils

def init_funcs_info_list(bv: BinaryView) -> list:
    """
    Initialize all the functions with their information.
    :param bv: The current binary view.
    :return: A list of dicts containing the function information.
    """
    funcs_info_list = []

    for f in bv.functions:
        main_info = {}
        callers_info_list = []
        callee_info_list = []
        indirect_transfers_info_list = []
        final_func_info = {}

        func_info = utils.FunctionInfo(f, bv)
        
        # Set the main function info for the target function
        main_info["start"] = func_info.start
        main_info["end"] = func_info.end
        main_info["name"] = func_info.name
        main_info["type"] = func_info.type
        main_info["args"] = func_info.args
        main_info["referenced_by"] = str(func_info.callers_refs_count)
        main_info["refers_to"] = str(func_info.callee_refs_count)
        main_info["basic_blocks"] = str(func_info.basic_blocks_count)
        main_info["indirect_transfers"] = str(func_info.indirect_transfers_count)

        # Set the 'refs from' info for the function
        for caller_info in func_info.callers_info:
            try:
              callers_info = {}
              callers_info["foreign_val"] = caller_info["foreign_val"]
              callers_info["from_addr"] = hex(caller_info["from_addr"])
              callers_info_list.append(callers_info)
            except KeyError:
                pass
        
        # Set the 'refs to' info for the function
        for info in func_info.callee_info:
          try:
            callee_info = {}
            callee_info["foreign_val"] = info["foreign_val"]
            callee_info["from_addr"] = hex(info["from_addr"])
            callee_info_list.append(callee_info)
          except KeyError:
              pass

        # Set the indirect transfers info for the function
        for call_info in func_info.indirect_transfers_info:
          try:
            calls_info = {}
            calls_info["foreign_val"] = call_info["foreign_val"]
            calls_info["from_addr"] = hex(call_info["from_addr"])
            indirect_transfers_info_list.append(calls_info)
          except KeyError:
              pass
        
        # Set the final results to be included in the list
        final_func_info["main_info"] = main_info
        final_func_info["callers_refs_info"] = callers_info_list
        final_func_info["callees_refs_info"] = callee_info_list
        final_func_info["indirect_transfers_info"] = indirect_transfers_info_list

        funcs_info_list.append(final_func_info)
        
    return funcs_info_list

def create_pane(context: UIActionContext) -> None:
    """
    Create the plugin pane.
    :param context: The action context.
    """
    if context.context and context.binaryView:
        bv = context.binaryView
        funcs_info_list = init_funcs_info_list(bv)
        widget = ui.PaneWidget(bv, funcs_info_list)
        pane = WidgetPane(widget, "IFL - Interactive Functions List")
        context.context.openPane(pane)

# Plugin registration
UIAction.registerAction("IFL")
UIActionHandler.globalActions().bindAction(
  "IFL", UIAction(create_pane)
)
Menu.mainMenu("Plugins").addAction("IFL", "IFL")