# The Qt code in this file is highly based on hasherezade's work so big thanks to her!

from PySide6.QtWidgets import (
    QVBoxLayout, 
    QTabWidget, 
    QTableView,
    QLabel,
    QWidget,
    QHBoxLayout,
    QComboBox,
    QLineEdit,
    QFrame,
    QPushButton,
    QSplitter
)

from PySide6 import QtCore

from binaryninja.binaryview import BinaryView
from binaryninja.function import Function
from binaryninja.log import Logger
from binaryninja import interaction

from . import utils

logger = Logger(session_id=0, logger_name="IFL")

class DataManager(QtCore.QObject):
    """
    Keeps track of the changes in data and signalizes them.
    """
    update_signal = QtCore.Signal()

    def __init__(self, parent=None) -> None:
        QtCore.QObject.__init__(self, parent=parent)
        self.current_addr = 0

    def set_current_addr(self, addr) -> None:
        """
        Set the current addr being handled.
        :param addr: The address to set.
        :return: None
        """
        if addr is None:
            addr = 0

        self.current_addr = addr
        self.update_signal.emit()

g_DataManager = DataManager()

def goto_address(bv: BinaryView, addr: int) -> None:
    """
    Navigate to the specified address.
    :param bv: The current binary view.
    :param addr: The address to navegate to.
    :return: None
    """
    view_name = "Linear:" + bv.view_type
    bv.navigate(view_name, addr)

class TableModel(QtCore.QAbstractTableModel):
    """
    The model for the top view (functions information).
    """
    COL_START = 0
    COL_END = 1
    COL_NAME = 2
    COL_TYPE = 3
    COL_ARGS = 4
    COL_CALLER_REFS = 5
    COL_CALLEE_REFS = 6
    COL_BB = 7
    COL_INDIRECT_TRANSF = 8

    COL_COUNT = 9

    header_names = [
        "Start", 
        "End", 
        "Name", 
        "Type", 
        "Args", 
        "Is Referenced by", 
        "Refers to", 
        "Basic Blocks", 
        "Indirect Transfers"
    ]
    
    def _display_header(self, orientation: QtCore.Qt.Orientation, col: int):
        """
        Retrieves a field description to be displayed in the header.
        :param orientation: The header orientation.
        :param col: The current column.
        :return: The column name.
        """
        if orientation == QtCore.Qt.Vertical:
            return None
        
        if col == self.COL_START:
            return self.header_names[self.COL_START]
        if col == self.COL_END:
            return self.header_names[self.COL_END]
        if col == self.COL_NAME:
            return self.header_names[self.COL_NAME]
        if col == self.COL_TYPE:
            return self.header_names[self.COL_TYPE]
        if col == self.COL_ARGS:
            return self.header_names[self.COL_ARGS]
        if col == self.COL_CALLER_REFS:
            return self.header_names[self.COL_CALLER_REFS]
        if col == self.COL_CALLEE_REFS:
            return self.header_names[self.COL_CALLEE_REFS]
        if col == self.COL_BB:
            return self.header_names[self.COL_BB]
        if col == self.COL_INDIRECT_TRANSF:
            return self.header_names[self.COL_INDIRECT_TRANSF]

        return None

    def _display_data(self, row: int, col: int):
        """
        Retrieve the data to be displayed according to the current row 
        and column.
        :param row: The current row.
        :param col: The current column.
        :return: The data to be displayed.
        """
        func_info = self.funcs_info_list[row]

        if col == self.COL_START:
            return hex(func_info["main_info"]["start"])
        if col == self.COL_END:
            return hex(func_info["main_info"]["end"])
        if col == self.COL_NAME:
            return func_info["main_info"]["name"]
        if col == self.COL_TYPE:
            return func_info["main_info"]["type"]
        if col == self.COL_ARGS:
            return func_info["main_info"]["args"]
        if col == self.COL_CALLER_REFS:
            return func_info["main_info"]["referenced_by"]
        if col == self.COL_CALLEE_REFS:
            return func_info["main_info"]["refers_to"]
        if col == self.COL_BB:
            return func_info["main_info"]["basic_blocks"]
        if col == self.COL_INDIRECT_TRANSF:
            return func_info["main_info"]["indirect_transfers"]
        
        return None

    def __init__(self, funcs_info_list) -> None:
        super(TableModel, self).__init__()

        self.funcs_info_list = funcs_info_list

# Qt API
    def rowCount(self, parent: QtCore.QModelIndex) -> int:
        return len(self.funcs_info_list)

    def columnCount(self, parent: QtCore.QModelIndex) -> int:
        return self.COL_COUNT

    def data(self, index: QtCore.QModelIndex, role: int):
        if not index.isValid():
            return None
        
        col = index.column()
        row = index.row()

        func_info = self.funcs_info_list[row]["main_info"]

        if role == QtCore.Qt.UserRole:
            if col == self.COL_END:
                return func_info["end"]
            return func_info["start"]
        elif role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
            return self._display_data(row, col)
        else:
            return None

    def headerData(self, 
                   section: int, 
                   orientation: QtCore.Qt.Orientation, 
                   role: int = QtCore.Qt.DisplayRole
                   ):
        if role == QtCore.Qt.DisplayRole:
            return self._display_header(orientation, section)
        else:
            return None

class RefsTableModel(QtCore.QAbstractTableModel):
    """
    The model for the bottom view (refs).
    """
    COL_FOREIGN_VAL = 0
    COL_FROM_ADDR = 1

    COL_COUNT = 2

    REF_FROM = 0
    REF_TO = 1
    REF_TRANSF = 2

    def _display_header(self, orientation, col: int) -> str:
        """
        Retrieves a field description to be displayed in the header.
        :param orientation: The header orientation.
        :param col: The current column.
        :return: The column name.
        """
        if orientation == QtCore.Qt.Vertical:
            return None
        if col == self.COL_FOREIGN_VAL:
            return "Foreign Val."
        if col == self.COL_FROM_ADDR:
            return "From Address"
        
        return None

    def _display_data(self, row: int, col: int) -> str:
        """
        Retrieve the data to be displayed according to the current row 
        and column.
        :param row: The current row.
        :param col: The current column.
        :return: The data to be displayed.
        """
        if len(self.refs_list) <= row:
            return None
  
        foreign_val = self.refs_list[row]["foreign_val"]
        from_addr = self.refs_list[row]["from_addr"]

        if col == self.COL_FOREIGN_VAL:
            return foreign_val
        if col == self.COL_FROM_ADDR:
            return from_addr
        
        return None

    def _get_addr_to_follow(self, row: int, col: int) -> int:
        """
        Check if the selected data is an address that can be followed
        in the Linear view.
        :param row: The current row.
        :param col: The current column.
        :return: The address itself.
        """
        value = ""
        addr = 0

        if col == self.COL_FOREIGN_VAL:
            value = self.refs_list[row]["foreign_val"]
        if col == self.COL_FROM_ADDR:
            value = self.refs_list[row]["from_addr"]
        
        # Check if its either a hex value or a func name being selected
        try:
            if value[:2] == "0x":
                value = int(value, 16)

                if self.bv.is_valid_offset(value):
                    addr = value
            else:
                f = self.bv.get_functions_by_name(value)[0]

                if isinstance(f, Function):
                    addr = f.start
        except:
            pass
        
        return addr

    def __init__(self, 
                 bv: BinaryView, 
                 funcs_info_list: list, 
                 ref_type: int
                 ) -> None:
        
        super(RefsTableModel, self).__init__()

        self.bv = bv
        self.funcs_info_list = funcs_info_list
        self.curr_index = (-1)
        self.ref_type = ref_type
        self.refs_list = []

    def find_addr_index(self, addr: int) -> int:
        """
        Search the given address on the list of functions.
        :param addr: The address to look for.
        :return: The function index found if any.
        """
        index = 0

        for func_info in self.funcs_info_list:
            if addr >= func_info["main_info"]["start"] and addr <= func_info["main_info"]["end"]:
                return index
            
            index += 1

        return (-1)

    def set_current_index(self, curr_index: int) -> None:
        self.curr_index = curr_index

        if self.curr_index == (-1) or self.curr_index >= len(self.funcs_info_list):
            # Reset list
            self.refs_list = []
        else:
            if self.ref_type == self.REF_FROM:
                self.refs_list = self.funcs_info_list[self.curr_index]["callers_refs_info"]
            if self.ref_type == self.REF_TO:
                self.refs_list = self.funcs_info_list[self.curr_index]["callees_refs_info"]
            if self.ref_type == self.REF_TRANSF:
                self.refs_list = self.funcs_info_list[self.curr_index]["indirect_transfers_info"]

        self.reset()

    def reset(self) -> None:
        self.beginResetModel()
        self.endResetModel()

    # Qt API
    def rowCount(self, parent: QtCore.QModelIndex) -> int:
        return len(self.refs_list)

    def columnCount(self, parent: QtCore.QModelIndex) -> int:
        return self.COL_COUNT

    def data(self, index: QtCore.QModelIndex, role: int):
        if not index.isValid():
            return None
        
        col = index.column()
        row = index.row()

        if role == QtCore.Qt.UserRole:
            return self._get_addr_to_follow(row, col)
        if role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
            return self._display_data(row, col)
        else:
            return None

    def headerData(self, 
                   section: int, 
                   orientation: QtCore.Qt.Orientation, 
                   role: int = QtCore.Qt.DisplayRole
                   ):
        if role == QtCore.Qt.DisplayRole:
            return self._display_header(orientation, section)
        else:
            return None

class FunctionsView(QTableView):
    def __init__(self, bv, func_model, data_manager):
        super(FunctionsView, self).__init__()

        self.bv = bv
        self.func_model = func_model
        self.data_manager = data_manager

    # Qt API
    def currentChanged(self, current, previous) -> None:
        index_data = self.get_index_data(current)
        self.data_manager.set_current_addr(index_data)

    def mouseDoubleClickEvent(self, event) -> None:
        event.accept()
        index = self.indexAt(event.pos())

        if not index.isValid():
            return
        
        data = self.get_index_data(index)

        if not data:
            super(QTableView, self).mouseDoubleClickEvent(event)
            return
        
        goto_address(self.bv, data)

        super(QTableView, self).mouseDoubleClickEvent(event)

    def get_index_data(self, index):
        if not index.isValid():
            return None
        
        try:
            data_val = index.data(QtCore.Qt.UserRole)
            if data_val is None:
                return None
            index_data = data_val
        except ValueError:
            return None
        
        return index_data

    def mousePressEvent(self, event) -> None:
        event.accept()
        super(QTableView, self).mousePressEvent(event)

    def leaveEvent(self, event) -> None:
        self.setCursor(QtCore.Qt.ArrowCursor)

class PaneWidget(QWidget):
    """
    Represents the main pane information.
    """
    def __init__(self, bv: BinaryView, funcs_info_list: list):
        QWidget.__init__(self)

        self.bv = bv
        self.funcs_info_list = funcs_info_list

        self.criterium_id = 0

        self.data_manager = DataManager()

        self.table_model = TableModel(self.funcs_info_list)

        self.funcs_sorted_model = QtCore.QSortFilterProxyModel()
        self.funcs_sorted_model.setSourceModel(self.table_model)
        self.funcs_sorted_model.setDynamicSortFilter(True)

        self.funcs_info_view = FunctionsView(self.bv, self.table_model, g_DataManager)
        self.funcs_info_view.setModel(self.funcs_sorted_model)
        self.funcs_info_view.setSortingEnabled(True)
        self.funcs_info_view.setWordWrap(False)
        self.funcs_info_view.horizontalHeader().setStretchLastSection(False)
        self.funcs_info_view.verticalHeader().show()

        self.table_model.setParent(self.funcs_sorted_model)
        self.funcs_sorted_model.setParent(self.funcs_info_view)

        self.refsfrom_model = RefsTableModel(self.bv, self.funcs_info_list, 0)
        self.refsfrom_view = FunctionsView(self.bv, self.refsfrom_model, self.data_manager)
        self._setup_sorted_model(self.refsfrom_view, self.refsfrom_model)
        self.refsfrom_view.setWordWrap(False)

        self.refsto_model = RefsTableModel(self.bv, self.funcs_info_list, 1)
        self.refsto_view = FunctionsView(self.bv, self.refsto_model, self.data_manager)
        self._setup_sorted_model(self.refsto_view, self.refsto_model)
        self.refsto_view.setWordWrap(False)

        self.indirect_transf_model = RefsTableModel(self.bv, self.funcs_info_list, 2)
        self.indirect_transf_view = FunctionsView(self.bv, self.indirect_transf_model, self.data_manager)
        self._setup_sorted_model(self.indirect_transf_view, self.indirect_transf_model)
        self.indirect_transf_view.setWordWrap(False)

        self.refs_tabs = QTabWidget()
        self.refs_tabs.insertTab(0, self.refsfrom_view, "Is refered by")
        self.refs_tabs.insertTab(1, self.refsto_view, "Refers to")
        self.refs_tabs.insertTab(2, self.indirect_transf_view, "Transfers indirectly to")

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("keyword")
        self.filter_edit.keyReleaseEvent = self._filter_key_event
        self.filter_edit.setFixedHeight(20)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(TableModel.header_names)
        self.filter_combo.setCurrentIndex(TableModel.COL_NAME)

        self.criterium_combo = QComboBox()
        criteria = ["contains", "matches"]
        self.criterium_combo.addItems(criteria)
        self.criterium_combo.setCurrentIndex(0)

        # Connect signals
        g_DataManager.update_signal.connect(self._addr_changed)
        self.filter_combo.activated.connect(self._filter_changed)
        self.criterium_combo.activated.connect(self._criterium_changed)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Where "))
        filter_layout.addWidget(self.filter_combo)
        filter_layout.addWidget(self.criterium_combo)
        filter_layout.addWidget(self.filter_edit)

        filter_panel = QFrame()
        filter_panel.setLayout(filter_layout)
        filter_panel.setFixedHeight(40)
        filter_panel.setAutoFillBackground(True)

        layout1 = QVBoxLayout()
        layout1.addWidget(filter_panel)
        layout1.addWidget(self.funcs_info_view)
        layout1.setContentsMargins(0, 0, 0, 0)
        panel1 = QFrame()
        panel1.setLayout(layout1)

        # Holds the function definition label text
        self.func_definition = QLabel("")

        layout2 = QVBoxLayout()
        layout2.addWidget(self.func_definition)
        layout2.addWidget(self.refs_tabs)
        layout2.addWidget(self._make_buttons())
        layout2.setContentsMargins(0, 10, 0, 0)
        panel2 = QFrame()
        panel2.setLayout(layout2)

        self.main_splitter = QSplitter()
        self.main_splitter.setOrientation(QtCore.Qt.Vertical)
        self.main_splitter.addWidget(panel1)
        self.main_splitter.addWidget(panel2)

        layout = QVBoxLayout()
        layout.addWidget(self.main_splitter)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    @staticmethod
    def _setup_sorted_model(view: QTableView, 
                            model: QtCore.QAbstractTableModel
                            ) -> QtCore.QSortFilterProxyModel:
        """
        Connect the given sorted data model with the given view.
        :param view: The view to be connected.
        :param model: The model to be connected.
        :return: The sorted model.
        """
        sorted_model = QtCore.QSortFilterProxyModel()
        sorted_model.setDynamicSortFilter(True)
        sorted_model.setSourceModel(model)

        view.setModel(sorted_model)
        view.setSortingEnabled(True)

        sorted_model.setParent(view)

        model.setParent(sorted_model)

        return sorted_model

#--------------------------------------------------------------------------
# Info updating
#--------------------------------------------------------------------------

    def _addr_changed(self) -> None:
        """
        A callback executed when the current address has changed.
        :return: None
        """
        global g_DataManager

        data = g_DataManager.current_addr
        self._update_views(data)

    @staticmethod
    def _update_current_addr(view: QTableView, 
                             refs_model: QtCore.QAbstractTableModel, 
                             addr: str
                             ) -> None:
        """
        Update the given data model to follow the given address.
        :param view: The table view.
        :param refs_model: The ref model.
        :param addr: The addr to be checked.
        :return: None
        """
        index = (-1)

        if addr:
            index = refs_model.find_addr_index(addr)

        refs_model.set_current_index(index)
        refs_model.reset()

        view.reset()
        view.repaint()

    def _update_refs_and_label_info(self, addr: int) -> None:
        """
        Update the number of occurrences in the tabs and also the text
        in the function description label.
        :param addr: The address of the selected function.
        :return: None
        """
        for func_info in self.funcs_info_list:
            func_addr = func_info["main_info"]["start"]

            if func_addr == addr:
                func_type = func_info["main_info"]["type"]
                func_name = func_info["main_info"]["name"]
                func_args = func_info["main_info"]["args"]
                label = f"{func_type} {func_name}{func_args}"
                # Update the function definition label text
                self.func_definition.setText(label)

                # Update the tabs titles
                refsfrom_count = func_info["main_info"]["referenced_by"]
                self.refs_tabs.setTabText(0, f"Is referred by {refsfrom_count}:")

                refsto_count = func_info["main_info"]["refers_to"]
                self.refs_tabs.setTabText(1, f"Refers to {refsto_count}:")

                indirect_transf_count = len(func_info["indirect_transfers_info"])
                self.refs_tabs.setTabText(2, f"Transfers indirectly to {indirect_transf_count}:")

    def _update_views(self, data: int) -> None:
        """
        Update the views to follow the proper address being selected.
        :param data: The selected data.
        :return: None
        """
        if not data:
            return
        
        self._update_current_addr(self.refsto_view, self.refsto_model, data)
        self._update_current_addr(self.refsfrom_view, self.refsfrom_model, data)
        self._update_current_addr(self.indirect_transf_view, self.indirect_transf_model, data)
        self._update_refs_and_label_info(data)

#--------------------------------------------------------------------------
# Filter callbacks
#--------------------------------------------------------------------------

    def _criterium_changed(self) -> None:
        """
        A callback executed when the criterium of sorting has changed
        and the data has to be sorted again.
        :return: None
        """
        self.criterium_id = self.criterium_combo.currentIndex()

        if self.criterium_id == 0:
            self.filter_edit.setPlaceholderText("keyword")
        else:
            self.filter_edit.setPlaceholderText("regex")

        self._filter_changed()

    def _apply_filter(self, col_value, str) -> None:
        """
        Apply a filter defined by the string on the data model.
        :param col_value: The column value selected.
        :param str: The string used to apply the filter.
        :return: None
        """
        if self.criterium_id == 0:
            self.funcs_sorted_model.setFilterFixedString(str)
        else:
            str = QtCore.QRegularExpression(str, QtCore.QRegularExpression.CaseInsensitiveOption)
            self.funcs_sorted_model.setFilterRegularExpression(str)

        self.funcs_sorted_model.setFilterKeyColumn(col_value)

    def _filter_changed(self) -> None:
        """
        Just a wrapper for the _apply_filter function.
        :return: None
        """
        self._apply_filter(self.filter_combo.currentIndex(), self.filter_edit.text())

    def _filter_key_event(self, event) -> None:
        """
        Callback used to get the filter text.
        :param event: The key event.
        :return: None
        """
        if event is not None:
            QLineEdit.keyReleaseEvent(self.filter_edit, event)

        self._filter_changed()

#--------------------------------------------------------------------------
# Buttons
#--------------------------------------------------------------------------

    def _make_buttons(self) -> QFrame:
        """
        Create the functions import/export buttons.
        :return: The buttons frame.
        """
        buttons_panel = QFrame()

        buttons_layout = QHBoxLayout()

        buttons_panel.setLayout(buttons_layout)

        import_button = QPushButton("Load names")
        import_button.clicked.connect(self._import_funcs)
        buttons_layout.addWidget(import_button)

        export_button = QPushButton("Save names")
        export_button.clicked.connect(self._export_funcs)
        buttons_layout.addWidget(export_button)

        return buttons_panel

    def _export_funcs(self) -> None:
        """
        Ask the user to select a file to save the functions names and
        call the function responsible for saving it.
        :return: None
        """
        filename = interaction.get_save_filename_input(
            "Enter the file name to save the exported functions."
            )

        if not filename:
            return

        extension = "." + filename.split(".")[-1]
        utils.save_funcs_to_file(self.bv, filename, extension)
        logger.log_info(f"Functions exported to {filename}.")

    def _import_funcs(self) -> None:
        """
        Ask the user to select a file to import the functions names from
        and call the function responsible for importing it.
        :return: None
        """
        filename = interaction.get_open_filename_input(
            "Filename:", "Tag files (*.tag);;Imports files (*.imports.txt);;All Files (*)"
            )

        if not filename:
            return

        image_base = 0
        original_base = self.bv.original_base
        new_base = interaction.get_text_line_input(f"Base address(current: {hex(original_base)})", 
                                                   "Define the optional base address"
                                                   )

        if new_base and utils.is_hex_str(new_base):
            image_base = int(new_base, 16)
        else:
            image_base = original_base
        
        loaded, comments = utils.import_funcs_from_file(self.bv, filename, image_base)

        if loaded == 0 and comments == 0:
            logger.log_error("Failed importing functions names (no matching offsets)!")
        else:
            logger.log_info(f"Imported {loaded} function names and {comments} comments!")
