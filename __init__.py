from binaryninjaui import (
    UIAction, 
    Menu,
    UIActionContext,
    UIActionHandler,
    WidgetPane
)

from binaryninja.binaryview import BinaryView
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.interaction import show_message_box
from binaryninja.enums import MessageBoxButtonSet, AnalysisState

from . import ui
from . import funcs

class InitFuncsInfoTableTask(BackgroundTaskThread):
    """
    Represents a background task.
    """
    def __init__(self, bv: BinaryView):
        super().__init__(
            initial_progress_text="[IFL] Loading functions info...",
            can_cancel=False,
        )
        
        self.bv = bv

    def run(self):
        """
        We use this function to initialize the funcs info list as a
        background task to avoid UI freezing during the info loading.
        Thanks to cxiao for this tip and feedback =)
        """
        funcs.FunctionsInfoMapper(self.bv)

        self.finish()

        return

def create_pane(context: UIActionContext) -> None:
    """
    Create the plugin pane.
    :param context: The action context.
    """
    bv = context.binaryView
    context = context.context

    if context and bv:
        # Attempt to make sure the analysis if finished and Binja has
        # all the funcs info in place
        if bv.analysis_info.state == AnalysisState.IdleState:
            task = InitFuncsInfoTableTask(bv)
            task.start()
            # Wait until the task is finished, otherwise the funcs info
            # list will be empty
            task.join()

            widget = ui.PaneWidget(bv, funcs.FunctionsInfoMapper.funcs_info_list)
            pane = WidgetPane(widget, "IFL - Interactive Functions List")
            context.openPane(pane)
        else:
            show_message_box(
                "IFL", 
                "Please wait until the analysis is finished.",
                MessageBoxButtonSet.OKButtonSet
		    )

# Plugin registration
UIAction.registerAction("IFL")
UIActionHandler.globalActions().bindAction(
    "IFL", UIAction(create_pane)
)
Menu.mainMenu("Plugins").addAction("IFL", "IFL")