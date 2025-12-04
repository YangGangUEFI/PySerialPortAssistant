import sys
import serial
import serial.tools.list_ports
import time
from datetime import datetime

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QComboBox, QLabel, QPushButton,
                               QPlainTextEdit, QCheckBox, QLineEdit, QFileDialog,
                               QProgressBar, QMessageBox, QGroupBox, QSpinBox)
from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtGui import QTextCursor, QTextCharFormat, QColor
from PySide6.QtNetwork import QTcpServer, QHostAddress, QAbstractSocket

# ==========================================
# 辅助函数：Hexdump 格式化
# ==========================================
def format_hexdump(data, start_offset=0):
    result = []
    # 每行16字节
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        # 1. 偏移量 (8位16进制)
        offset_str = f"{start_offset + i:08X}"

        # 2. 十六进制部分 (每字节2位，不够16字节补空格)
        hex_str = ' '.join(f"{b:02X}" for b in chunk)
        padding = "   " * (16 - len(chunk))

        # 3. ASCII 部分 (不可见字符用点代替)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

        # 组合: 偏移量: Hex部分 | ASCII
        line = f"{offset_str}: {hex_str}{padding}  |{ascii_str}|"
        result.append(line)
    return '\n'.join(result)

# ==========================================
# 核心逻辑：串口接收线程
# ==========================================
class SerialWorker(QThread):
    data_received = Signal(bytes)
    error_occurred = Signal(str)

    def __init__(self, port, baud, data_bits, parity, stop_bits, flow_control):
        super().__init__()
        self.port_name = port
        self.baud = baud
        self.data_bits = data_bits
        self.parity = parity
        self.stop_bits = stop_bits
        self.flow_control = flow_control
        self.is_running = True
        self.serial_port = serial.Serial()

    def run(self):
        try:
            parity_dict = {'None': serial.PARITY_NONE, 'Even': serial.PARITY_EVEN,
                           'Odd': serial.PARITY_ODD, 'Mark': serial.PARITY_MARK, 'Space': serial.PARITY_SPACE}
            stop_dict = {'1': serial.STOPBITS_ONE, '1.5': serial.STOPBITS_ONE_POINT_FIVE, '2': serial.STOPBITS_TWO}

            xonxoff = False
            rtscts = False
            if self.flow_control == 'XON/XOFF':
                xonxoff = True
            elif self.flow_control == 'RTS/CTS':
                rtscts = True

            self.serial_port = serial.Serial(
                port=self.port_name,
                baudrate=int(self.baud),
                bytesize=int(self.data_bits),
                parity=parity_dict[self.parity],
                stopbits=stop_dict[self.stop_bits],
                xonxoff=xonxoff,
                rtscts=rtscts,
                timeout=0.1
            )

            while self.is_running and self.serial_port.is_open:
                if self.serial_port.in_waiting:
                    data = self.serial_port.read(self.serial_port.in_waiting)
                    if data:
                        self.data_received.emit(data)
                else:
                    time.sleep(0.01)

        except Exception as e:
            self.error_occurred.emit(str(e))
        finally:
            if self.serial_port and self.serial_port.is_open:
                self.serial_port.close()

    def stop(self):
        self.is_running = False
        self.wait()

    def send_data(self, data):
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.write(data)

# ==========================================
# 核心逻辑：文件发送线程
# ==========================================
class FileSender(QThread):
    progress_update = Signal(int, int)
    finished_signal = Signal()
    error_signal = Signal(str)

    def __init__(self, serial_obj, file_path, baud_rate):
        super().__init__()
        self.serial_obj = serial_obj
        self.file_path = file_path
        self.baud_rate = int(baud_rate)
        self.is_running = True

    def run(self):
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()

            total_len = len(data)
            sent_len = 0
            chunk_size = 1024
            bytes_per_sec = self.baud_rate / 10.0
            delay_per_chunk = chunk_size / bytes_per_sec

            for i in range(0, total_len, chunk_size):
                if not self.is_running:
                    break
                chunk = data[i:i+chunk_size]
                self.serial_obj.write(chunk)
                sent_len += len(chunk)
                self.progress_update.emit(sent_len, total_len)

                if delay_per_chunk > 0.001:
                    time.sleep(delay_per_chunk)
                else:
                    time.sleep(0.001)

            self.finished_signal.emit()

        except Exception as e:
            self.error_signal.emit(str(e))

    def stop(self):
        self.is_running = False

# ==========================================
# TCP Server (转发器)
# ==========================================
class TcpForwarder(QTcpServer):
    def __init__(self, port, parent=None):
        super().__init__(parent)
        self.port = port
        self.clients = []
        if not self.listen(QHostAddress.SpecialAddress.Any, self.port):
            raise Exception(f"无法监听端口 {self.port}: {self.errorString()}")
        self.newConnection.connect(self.handle_connection)

    def handle_connection(self):
        while self.hasPendingConnections():
            client = self.nextPendingConnection()
            self.clients.append(client)
            client.disconnected.connect(lambda c=client: self.clients.remove(c))

    def broadcast(self, data):
        for client in self.clients[:]:
            if client.state() == QAbstractSocket.SocketState.ConnectedState:
                client.write(data)

# ==========================================
# 主界面
# ==========================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Serial Port Assistant")
        self.resize(1100, 750)

        self.raw_data_buffer = bytearray()

        self.serial_thread = None
        self.tcp_server = None
        self.file_sender = None

        self.search_matches = []
        self.current_match_index = -1

        self.init_ui()
        self.refresh_ports()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # 1. 设置区
        settings_layout = QHBoxLayout()
        grp_serial = QGroupBox("串口设置")
        serial_layout = QHBoxLayout(grp_serial)

        self.combo_port = QComboBox()
        self.combo_port.currentIndexChanged.connect(self.combo_port_tooltip)

        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.clicked.connect(self.refresh_ports)

        self.combo_baud = QComboBox()
        self.combo_baud.addItems([str(b) for b in [9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]])
        self.combo_baud.setCurrentText("115200")

        self.combo_data = QComboBox()
        self.combo_data.addItems(['5','6','7','8'])
        self.combo_data.setCurrentText('8')
        self.combo_stop = QComboBox()
        self.combo_stop.addItems(['1','1.5','2'])
        self.combo_stop.setCurrentText('1')
        self.combo_parity = QComboBox()
        self.combo_parity.addItems(['None','Even','Odd','Mark','Space'])
        self.combo_flow = QComboBox()
        self.combo_flow.addItems(['None','RTS/CTS','XON/XOFF'])

        self.btn_open = QPushButton("打开串口")
        self.btn_open.setCheckable(True)
        self.btn_open.clicked.connect(self.toggle_serial)

        serial_layout.addWidget(QLabel("端口:"))
        serial_layout.addWidget(self.combo_port)
        serial_layout.addWidget(self.btn_refresh)
        serial_layout.addWidget(QLabel("波特率:"))
        serial_layout.addWidget(self.combo_baud)
        serial_layout.addWidget(QLabel("数据:"))
        serial_layout.addWidget(self.combo_data)
        serial_layout.addWidget(QLabel("停止:"))
        serial_layout.addWidget(self.combo_stop)
        serial_layout.addWidget(QLabel("校验:"))
        serial_layout.addWidget(self.combo_parity)
        serial_layout.addWidget(QLabel("流控:"))
        serial_layout.addWidget(self.combo_flow)
        serial_layout.addWidget(self.btn_open)
        settings_layout.addWidget(grp_serial)

        grp_tcp = QGroupBox("TCP转发")
        tcp_layout = QVBoxLayout(grp_tcp)
        h_tcp = QHBoxLayout()
        self.chk_tcp = QCheckBox("启用服务器")
        self.spin_tcp_port = QSpinBox()
        self.spin_tcp_port.setRange(1024, 65535)
        self.spin_tcp_port.setValue(8888)
        self.chk_tcp.stateChanged.connect(self.toggle_tcp)
        h_tcp.addWidget(self.chk_tcp)
        h_tcp.addWidget(QLabel("端口:"))
        h_tcp.addWidget(self.spin_tcp_port)
        tcp_layout.addLayout(h_tcp)
        settings_layout.addWidget(grp_tcp)
        main_layout.addLayout(settings_layout)

        # 2. 控制区
        ctrl_layout = QHBoxLayout()
        self.chk_hex_display = QCheckBox("HEX显示 (Hexdump)")
        self.chk_hex_display.stateChanged.connect(self.update_display_mode)
        self.chk_timestamp = QCheckBox("时间戳")

        btn_clear = QPushButton("清空显示")
        btn_clear.clicked.connect(self.clear_display)

        btn_save = QPushButton("保存数据")
        btn_save.clicked.connect(self.save_data)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("搜索内容...")
        self.chk_search_hex = QCheckBox("HEX搜索")
        btn_find = QPushButton("查找")
        btn_find.clicked.connect(self.perform_search)
        btn_prev = QPushButton("<")
        btn_prev.clicked.connect(lambda: self.navigate_search(-1))
        btn_next = QPushButton(">")
        btn_next.clicked.connect(lambda: self.navigate_search(1))

        btn_clear_search = QPushButton("清除搜索")
        btn_clear_search.clicked.connect(self.clear_search_highlight)
        self.lbl_search_idx = QLabel("0/0")

        ctrl_layout.addWidget(self.chk_hex_display)
        ctrl_layout.addWidget(self.chk_timestamp)
        ctrl_layout.addWidget(btn_clear)
        ctrl_layout.addWidget(btn_save)
        ctrl_layout.addStretch()
        ctrl_layout.addWidget(QLabel("搜索:"))
        ctrl_layout.addWidget(self.txt_search)
        ctrl_layout.addWidget(self.chk_search_hex)
        ctrl_layout.addWidget(btn_find)
        ctrl_layout.addWidget(btn_prev)
        ctrl_layout.addWidget(self.lbl_search_idx)
        ctrl_layout.addWidget(btn_next)
        ctrl_layout.addWidget(btn_clear_search)
        main_layout.addLayout(ctrl_layout)

        # 3. 接收区
        self.txt_receive = QPlainTextEdit()
        self.txt_receive.setReadOnly(True)
        # 移除 BlockCount 限制，允许无限显示（直到内存耗尽）
        # self.txt_receive.setMaximumBlockCount(5000)
        font = self.txt_receive.font()
        font.setFamily("Consolas")
        font.setPointSize(10)
        self.txt_receive.setFont(font)
        self.txt_receive.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        main_layout.addWidget(self.txt_receive, stretch=2)

        # 4. 发送区
        send_group = QGroupBox("发送区")
        send_layout = QVBoxLayout(send_group)
        h_send_opt = QHBoxLayout()
        self.chk_send_hex = QCheckBox("HEX发送")
        self.chk_send_newline = QCheckBox("加回车换行(\\r\\n)")
        h_send_opt.addWidget(self.chk_send_hex)
        h_send_opt.addWidget(self.chk_send_newline)
        h_send_opt.addStretch()
        h_input = QHBoxLayout()
        self.txt_send = QLineEdit()
        self.txt_send.returnPressed.connect(self.send_msg)
        btn_send = QPushButton("发送")
        btn_send.clicked.connect(self.send_msg)
        h_input.addWidget(self.txt_send)
        h_input.addWidget(btn_send)
        h_file = QHBoxLayout()
        self.lbl_file_status = QLabel("未选择文件")
        self.progress_bar = QProgressBar()
        btn_file = QPushButton("选择文件")
        btn_file.clicked.connect(self.select_file)
        self.btn_stop_file = QPushButton("停止发送")
        self.btn_stop_file.setEnabled(False)
        self.btn_stop_file.clicked.connect(self.stop_file_send)
        h_file.addWidget(btn_file)
        h_file.addWidget(self.lbl_file_status)
        h_file.addWidget(self.progress_bar)
        h_file.addWidget(self.btn_stop_file)
        send_layout.addLayout(h_send_opt)
        send_layout.addLayout(h_input)
        send_layout.addLayout(h_file)
        main_layout.addWidget(send_group)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")

    # ================= 逻辑功能 =================

    def combo_port_tooltip(self, index):
        port_desc = self.combo_port.itemData(index, Qt.ItemDataRole.ToolTipRole)
        if port_desc:
            self.combo_port.setToolTip(port_desc)

    def refresh_ports(self):
        self.combo_port.clear()
        ports = serial.tools.list_ports.comports()
        for p in ports:
            self.combo_port.addItem(p.device, userData=p.device)
            display_name = f"{p.device} - {p.description}"
            self.combo_port.setItemData(self.combo_port.count() - 1, display_name, Qt.ItemDataRole.ToolTipRole)

        self.combo_port_tooltip(0)

    def toggle_serial(self):
        if self.btn_open.isChecked():
            port = self.combo_port.currentData()
            if not port:
                self.btn_open.setChecked(False)
                return
            self.serial_thread = SerialWorker(
                port, self.combo_baud.currentText(), self.combo_data.currentText(),
                self.combo_parity.currentText(), self.combo_stop.currentText(), self.combo_flow.currentText()
            )
            self.serial_thread.data_received.connect(self.handle_data_received)
            self.serial_thread.error_occurred.connect(self.handle_serial_error)
            self.serial_thread.start()
            self.btn_open.setText("关闭串口")
            self.status_bar.showMessage(f"已连接 {port}")
            self.disable_settings(True)
        else:
            if self.serial_thread:
                self.serial_thread.stop()
            self.btn_open.setText("打开串口")
            self.status_bar.showMessage("串口已关闭")
            self.disable_settings(False)

    def disable_settings(self, disable):
        self.combo_baud.setDisabled(disable)
        self.combo_port.setDisabled(disable)
        self.btn_refresh.setDisabled(disable)

    def handle_serial_error(self, msg):
        QMessageBox.critical(self, "串口错误", msg, QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)
        self.btn_open.setChecked(False)
        self.toggle_serial()

    def handle_data_received(self, data):
        current_offset = len(self.raw_data_buffer)

        # 1. 核心：存入原始缓冲
        self.raw_data_buffer.extend(data)

        # 2. TCP 转发
        if self.tcp_server:
            self.tcp_server.broadcast(data)

        # 3. 界面显示
        self.append_to_display(data, current_offset)

    def append_to_display(self, data, offset_start=0):
        self.txt_receive.moveCursor(QTextCursor.MoveOperation.End)

        text_to_show = ""
        timestamp = ""
        if self.chk_timestamp.isChecked():
            timestamp = f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] "

        if self.chk_hex_display.isChecked():
            hexdump_str = format_hexdump(data, offset_start)
            if timestamp:
                text_to_show = f"\n{timestamp}\n{hexdump_str}"
            else:
                if self.txt_receive.document().blockCount() > 1:
                    text_to_show = "\n" + hexdump_str
                else:
                    text_to_show = hexdump_str
        else:
            try:
                decoded = data.decode('utf-8')
            except UnicodeDecodeError:
                decoded = data.decode('latin-1')
            text_to_show = f"{timestamp}{decoded}"

        self.txt_receive.insertPlainText(text_to_show)
        sb = self.txt_receive.verticalScrollBar()
        sb.setValue(sb.maximum())

    def update_display_mode(self):
        # 切换显示模式，重新渲染
        self.txt_receive.clear()

        data_to_render = self.raw_data_buffer

        if not data_to_render:
            return

        # 全部数据重绘，offset 从 0 开始
        self.append_to_display(data_to_render, 0)

    def clear_display(self):
        self.txt_receive.clear()
        self.raw_data_buffer.clear()
        self.status_bar.showMessage("缓冲区已清空")

    def save_data(self):
        if not self.raw_data_buffer:
            QMessageBox.warning(self, "提示", "没有数据可保存", QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)
            return

        if self.chk_hex_display.isChecked():
            default_filter = "Binary Files (*.bin);;Text Files (*.txt);;All Files (*)"
            default_ext = "bin"
        else:
            default_filter = "Text Files (*.txt);;Binary Files (*.bin);;All Files (*)"
            default_ext = "txt"

        filename, filter_used = QFileDialog.getSaveFileName(self, "保存数据", f"saved_data.{default_ext}", default_filter)

        if filename:
            try:
                with open(filename, 'wb') as f:
                    f.write(self.raw_data_buffer)
                QMessageBox.information(self, "成功", f"成功保存 {len(self.raw_data_buffer)} 字节数据")
            except Exception as e:
                QMessageBox.critical(self, "错误", str(e), QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)

    def send_msg(self):
        if not self.serial_thread or not self.serial_thread.serial_port.is_open:
            QMessageBox.warning(self, "错误", "串口未打开", QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)
            return
        content = self.txt_send.text()
        if not content:
            return
        data_to_send = b''
        try:
            if self.chk_send_hex.isChecked():
                clean_hex = content.replace(" ", "")
                data_to_send = bytes.fromhex(clean_hex)
            else:
                data_to_send = content.encode('utf-8')
            if self.chk_send_newline.isChecked():
                data_to_send += b'\r\n'
            self.serial_thread.send_data(data_to_send)
        except ValueError:
            QMessageBox.warning(self, "格式错误", "HEX格式无效", QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)

    def select_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if fname:
            self.current_file_path = fname
            self.lbl_file_status.setText(fname)
            if not self.serial_thread or not self.serial_thread.serial_port.is_open:
                QMessageBox.warning(self, "提示", "请先打开串口", QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)
                return
            self.start_file_send(fname)

    def start_file_send(self, fname):
        if not self.serial_thread or not self.serial_thread.serial_port.is_open:
            QMessageBox.warning(self, "提示", "请先打开串口", QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)
            return
        self.file_sender = FileSender(self.serial_thread.serial_port, fname, self.combo_baud.currentText())
        self.file_sender.progress_update.connect(self.update_progress)
        self.file_sender.finished_signal.connect(lambda: self.status_bar.showMessage("文件发送完成"))
        self.file_sender.finished_signal.connect(lambda: self.btn_stop_file.setEnabled(False))
        self.file_sender.error_signal.connect(lambda e: QMessageBox.critical(self, "发送错误", e, QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton))
        self.btn_stop_file.setEnabled(True)
        self.file_sender.start()

    def update_progress(self, current, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        percent = (current / total) * 100
        self.status_bar.showMessage(f"正在发送文件... {percent:.1f}%")

    def stop_file_send(self):
        if self.file_sender:
            self.file_sender.stop()
            self.status_bar.showMessage("文件发送已中断")
            self.btn_stop_file.setEnabled(False)

    def toggle_tcp(self, state):
        if state == 2:
            try:
                self.tcp_server = TcpForwarder(self.spin_tcp_port.value())
                self.status_bar.showMessage(f"TCP转发服务启动于端口 {self.spin_tcp_port.value()}")
            except Exception as e:
                QMessageBox.critical(self, "TCP错误", str(e), QMessageBox.StandardButton.Ok, QMessageBox.StandardButton.NoButton)
                self.chk_tcp.setChecked(False)
        else:
            if self.tcp_server:
                self.tcp_server.close()
                self.tcp_server = None
                self.status_bar.showMessage("TCP转发服务已停止")

    def perform_search(self):
        text = self.txt_search.text()
        if not text:
            return
        self.clear_search_highlight()
        self.search_matches = []
        doc = self.txt_receive.document()
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor("yellow"))
        cursor = QTextCursor(doc)
        while True:
            cursor = doc.find(text, cursor)
            if cursor.isNull():
                break
            cursor.mergeCharFormat(highlight_format)
            self.search_matches.append(cursor)
        count = len(self.search_matches)
        self.current_match_index = -1
        if count > 0:
            self.current_match_index = 0
            self.highlight_current_match()
        self.lbl_search_idx.setText(f"{1 if count>0 else 0}/{count}")

    def navigate_search(self, direction):
        if not self.search_matches:
            return
        self.current_match_index += direction
        if self.current_match_index >= len(self.search_matches):
            self.current_match_index = 0
        elif self.current_match_index < 0:
            self.current_match_index = len(self.search_matches) - 1
        self.highlight_current_match()
        self.lbl_search_idx.setText(f"{self.current_match_index+1}/{len(self.search_matches)}")

    def highlight_current_match(self):
        orange_fmt = QTextCharFormat()
        orange_fmt.setBackground(QColor("orange"))
        yellow_fmt = QTextCharFormat()
        yellow_fmt.setBackground(QColor("yellow"))
        for cursor in self.search_matches:
            cursor.mergeCharFormat(yellow_fmt)
        curr_cursor = self.search_matches[self.current_match_index]
        curr_cursor.mergeCharFormat(orange_fmt)
        self.txt_receive.setTextCursor(curr_cursor)

    def clear_search_highlight(self):
        cursor = QTextCursor(self.txt_receive.document())
        cursor.select(QTextCursor.SelectionType.Document)
        fmt = QTextCharFormat()
        fmt.setBackground(Qt.GlobalColor.transparent)
        cursor.mergeCharFormat(fmt)
        self.search_matches = []
        self.lbl_search_idx.setText("0/0")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
