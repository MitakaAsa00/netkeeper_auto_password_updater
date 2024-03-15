import serial
import serial.tools.list_ports
import time
import re
import io
import math
from flask import Flask
import threading
import logging
from serial.serialutil import SerialException

netkeeper_password = None
netkeeper_password_expiry_time = None
netkeeper_addr_smsc_addr = "8613742583001"
netkeeper_addr = "86106593005"
netkeeper_password_query_msg = "mm"
netkeeper_password_update_flag = True

log_file_name = "sms_pdu.log"
log_level = logging.DEBUG

log_format = logging.Formatter("%(asctime)s - [%(levelname)s] - %(message)s")
log_file_handler = logging.FileHandler(log_file_name, encoding="utf-8")
log_file_handler.setFormatter(log_format)
log_stream_handler = logging.StreamHandler()
log_stream_handler.setFormatter(log_format)

logger = logging.getLogger(__name__)
logger.setLevel(log_level)
logger.addHandler(log_file_handler)
logger.addHandler(log_stream_handler)


def reverse_semi_byte(raw_bytes: bytes) -> bytes:
    reversed_bytes: bytes = (int.from_bytes(raw_bytes) >> 4 | int.from_bytes(raw_bytes) << 4 & 0xff).to_bytes()
    return reversed_bytes


def reverse_semi_bytearray(raw_bytearray: bytearray) -> bytearray:
    reversed_bytearray: bytearray = bytearray()
    for i in range(len(raw_bytearray)):
        reversed_bytearray.extend(reverse_semi_byte(raw_bytearray[i].to_bytes()))
    return reversed_bytearray


def odd_fill(raw_string: str) -> str:
    return raw_string + "f" if (raw_string.__len__() % 2) else raw_string


def find_serial_port(device_name) -> str:
    serial_ports = serial.tools.list_ports.comports()
    for port in serial_ports:
        if device_name in port.description:
            return port.device
    return None


class AddrField:
    # 9.1.2.5 Address fields *注意区别 AddrField 和 SMSCAddrField **没找到有关于SMSCAddrField和AddrField定义区别的官方文档, 约定俗成?
    """
    The Type-of-Address field format is as follows:

    1 + Type-of-number + Numbering-plan-identification

    Type-of-number:
        Bits	6 5 4
                0 0 0  Unknown 1)
                0 0 1  International number 2)
                0 1 0  National number 3)
                0 1 1  Network specific number 4)
                1 0 0  Subscriber number 5)
                1 0 1  Alphanumeric, (coded according to 3GPP TS 23.038 [9] GSM 7-bit default alphabet)
                1 1 0  Abbreviated number
                1 1 1  Reserved for extension

    Numbering-plan-identification
        Bits	3 2 1 0
                0 0 0 0  Unknown
                0 0 0 1  ISDN/telephone numbering plan (E.164 [17]/E.163[18])
                0 0 1 1  Data numbering plan (X.121)
                0 1 0 0  Telex numbering plan
                0 1 0 1  Service Centre Specific plan 1)
                0 1 1 0  Service Centre Specific plan 1)
                1 0 0 0  National numbering plan
                1 0 0 1  Private numbering plan
                1 0 1 0  ERMES numbering plan (ETSI DE/PS 3 01-3)
                1 1 1 1  Reserved for extension
                All other values are reserved.
    """

    def __init__(self, _type: str, length: int, type_of_address: int, type_of_number: int, number_plan_identification: int, service_centre_address: bytearray):
        self.__type: str = _type
        self.length: int = length
        self.service_centre_address_type: bytes = (
                type_of_address |
                type_of_number |
                number_plan_identification
        ).to_bytes()
        self.service_centre_address: bytearray = service_centre_address

    @classmethod
    def init_by_addr(cls, _type: str, addr: str):
        type_of_address: int = 0b1 << 7  # bit 7
        type_of_number: int = 0b001 << 4  # bit 6 5 4
        number_plan_identification: int = 0b0001  # bit 3 2 1 0
        service_centre_address: bytearray = reverse_semi_bytearray(bytearray.fromhex(odd_fill(addr)))

        # AddrField的length为 len(addr)
        # SMSCAddrField的len为 1Byte(type) + nByte(addr)
        if _type == "addr":
            length: int = len(addr)
        elif _type == "smscaddr":
            # service_centre_address_type 1Byte
            length: int = 1 + len(service_centre_address)
        else:
            print("wrong addr type")
            raise Exception

        return cls(_type, length, type_of_address, type_of_number, number_plan_identification, service_centre_address)

    @classmethod
    def init_by_raw(cls, _type: str, length: int, service_centre_address_type: bytes, service_centre_address: bytes):
        _ = int.from_bytes(service_centre_address_type)
        type_of_address: int = _ & 0b10000000  # bit 7
        type_of_number: int = _ & 0b01110000  # bit 6 5 4
        number_plan_identification: int = _ & 0b00001111  # bit 3 2 1 0

        return cls(_type, length, type_of_address, type_of_number, number_plan_identification, bytearray(service_centre_address))

    def to_unicode_hex(self) -> str:
        return self.length.to_bytes().hex() + self.service_centre_address_type.hex() + self.service_centre_address.hex()

    def to_unicode_byte(self) -> bytes:
        return self.length.to_bytes() + self.service_centre_address_type + self.service_centre_address


class SMSSubmit:  # 9.2.2.2 SMS-SUBMIT type
    """
    Abbr.   Reference   p1) p2) Description
    TP-MTI  TP-Message-Type-Indicator   M   2b  Parameter describing the message type.
    TP-RD   TP-Reject-Duplicates    M   b   Parameter indicating whether or not the SC shall accept an SMS-SUBMIT for an SM still held in the SC which has the same TP-MR and the same TP-DA as a previously submitted SM from the same OA
    TP-VPF  TP-Validiti-Period-Format   M   2b  Parameter indicating whether or not the TP-VP field is present.
    TP-RP   TP-Reply-Path   M   b   Parameter indicating the request for Reply Path.
    TP-UDHI TP-User-Data-Header-Indicator   O   b   Parameter indicating that the TP-UD field contains a Header.
    TP-SRR  TP-Status-Report-Request    O   b   Parameter indicating if the MS is requesting a status report.
    TP-MR   TP-Message-Reference    M   I   Parameter identifying the SMS-SUBMIT.
    TP-DA   TP-Destination-Address  M   2-12o   Address of the destination SME.
    TP-PID  TP-Protocol-Identifier  M   o   Parameter identifying the above layer protocol, if any.
    TP-DCS  TP-Data-Coding-Scheme   M   o   Parameter identifying the coding scheme within the TP-User-Data.
    TP-VP   TP-Validity-Period  O   o/7o    Parameter identifying the time from where the message is no longer valid.
    TP-UDL  TP-User-Data-Length M   I   Parameter indicating the length of the TP-User-Data field to follow.
    TP-UD   TP-User-Data    O   3)

    1) Provision;  Mandatory (M) or Optional (O).
    2) Representation; Integer (I), bit (b), 2 bits (2b), Octet (o), 7 octets (7o), 2-12 octets (2-12o).
    3) Dependent on the TP-DCS.
    """

    def __init__(self, service_centre_addr: str, dest_addr: str, content: str):
        self.SMSC_ADDR: AddrField = AddrField.init_by_addr("smscaddr", service_centre_addr)
        # 9.2.3.1 TP-Message-Type-Indicator (TP-MTI) 短信类型: SMS-SUBMIT
        _TP_MTI: int = 0b01  # bit 1 0
        # 9.2.3.25 TP-Reject-Duplicates (TP-RD) 短信中心不拒绝重复短信 (相同TP-MR, TP-DA, OA)
        _TP_RDI: int = 0b0 << 2  # bit 2
        # 9.2.3.3 TP-Validity-Period-Format (TP-VPF) 有效期格式: TP-VP field present - relative format
        _TP_VRF: int = 0b10 << 3  # bit 4 3
        # 9.2.3.17 TP-Reply-Path (TP-RP) 应答路径: 无 (不设置应答路径) *详见文档
        _TP_RP: int = 0b0 << 5  # bit 5
        # 9.2.3.23 TP-User-Data-Header-Indicator (TP-UDHI) 用户数据头标识: 否 (TP-UD是否包含TP-UDH)
        _TP_UDHI: int = 0b0 << 6  # bit 6
        # 9.2.3.5 TP-Status-Report-Request (TP-SRR) 状态报告要求: 否 (不返回状态)
        _TP_SRR: int = 0b0 << 7  # bit 7
        self.TP_FIRST_OCTET: bytes = (
                _TP_MTI |
                _TP_RDI |
                _TP_VRF |
                _TP_RP |
                _TP_UDHI |
                _TP_SRR
        ).to_bytes()
        # 9.2.3.6 TP-Message-Reference (TP-MR) 信息标识号 （类型为Integer 但是值为0~255? 1Byte还是2Byte?)
        self.TP_MR: int = 0x00
        # 9.2.3.8 TP-Destination-Address (TP-DA) 目标地址 (同 9.1.2.5 Address fields)
        self.TP_DA: AddrField = AddrField.init_by_addr("addr", dest_addr)
        # 9.2.3.9 TP-Protocol-Identifier (TP-PID) 协议标识? (引用更高级的协议或特定协议? 缺省)
        self.TP_PID: int = 0x00
        # 9.2.3.10 TP-Data-Coding-Scheme (TP-DCS) 编码类型: UCS2 (0x08)
        self.TP_DCS: int = 0x08
        # 9.2.3.12 TP-Validity-Period (TP-VP) 有效期
        self.TP_VP: int = 0x00

        # 9.2.3.24 TP-User Data (TP-UD) 短信内容 (utf-16be代替ucs2)
        self.TP_UD: bytes = content.encode("utf-16be")

        # 9.2.3.16 TP-User-Data-Length (TP-UDL) 短信长度
        self.TP_UDL: int = len(self.TP_UD)

    def to_unicode_hex(self) -> str:
        _ = self.SMSC_ADDR.to_unicode_hex() + \
            self.TP_FIRST_OCTET.hex() + \
            self.TP_MR.to_bytes().hex() + \
            self.TP_DA.to_unicode_hex() + \
            self.TP_PID.to_bytes().hex() + \
            self.TP_DCS.to_bytes().hex() + \
            self.TP_VP.to_bytes().hex() + \
            self.TP_UDL.to_bytes().hex() + \
            self.TP_UD.hex()
        return _

    def to_unicode_hex_tpdu(self) -> str:
        _ = self.TP_FIRST_OCTET.hex() + \
            self.TP_MR.to_bytes().hex() + \
            self.TP_DA.to_unicode_hex() + \
            self.TP_PID.to_bytes().hex() + \
            self.TP_DCS.to_bytes().hex() + \
            self.TP_VP.to_bytes().hex() + \
            self.TP_UDL.to_bytes().hex() + \
            self.TP_UD.hex()
        return _


class SMSDelivery:
    def __init__(self, pdu_string: str):
        pdu_stream: io.BytesIO = io.BytesIO(bytes.fromhex(pdu_string))

        _SMSC_addr_len: int = int.from_bytes(pdu_stream.read(1))
        _SMSC_addr_type: bytes = pdu_stream.read(1)
        _SMSC_addr: bytes = pdu_stream.read(_SMSC_addr_len - 1)
        self.SMSC_ADDR: AddrField = AddrField.init_by_raw("smscaddr", _SMSC_addr_len, _SMSC_addr_type, _SMSC_addr)

        self.TP_FIRST_OCTET: bytes = pdu_stream.read(1)

        _TP_OA_LEN: int = int.from_bytes(pdu_stream.read(1))
        _TP_OA_TYPE: bytes = pdu_stream.read(1)
        _TP_OA_ADDR: bytes = pdu_stream.read(_TP_OA_LEN // 2 if _TP_OA_LEN % 2 == 0 else (_TP_OA_LEN + 1) // 2)
        self.TP_OA: AddrField = AddrField.init_by_raw("addr", _TP_OA_LEN, _TP_OA_TYPE, _TP_OA_ADDR)

        self.TP_PID: int = int.from_bytes(pdu_stream.read(1))
        self.TP_DCS: int = int.from_bytes(pdu_stream.read(1))
        self.TP_SCTS: int = int.from_bytes(pdu_stream.read(7))

        self.TP_UDL: int = int.from_bytes(pdu_stream.read(1))
        self.TP_UD: bytes = pdu_stream.read(self.TP_UDL)

    def get_user_data_string(self) -> str:
        return self.TP_UD.decode("utf-16be")


def execute_at_command(serial_obj: serial.Serial, command: str, clear_before_cmd: bool = True, clear_after_cmd: bool = True) -> bytes:
    if clear_before_cmd:
        serial_obj.reset_input_buffer()
        serial_obj.flush()
    serial_obj.write(f"{command}\r".encode())
    serial_obj.readline()
    resp = serial_obj.readline().strip()
    if clear_after_cmd:
        serial_obj.reset_input_buffer()
        serial_obj.flush()
    return resp


def is_ready(serial_obj: serial.Serial, retry_count: int = 10) -> bool:
    check_list = [
        {
            "cmd": "AT+CPIN?",
            "check": rb"CPIN: READY$"
        },
        {
            "cmd": "AT+CSQ",
            "check": rb"CSQ: \b(?:1[8-9]|2[0-9]|30|31)\b,99"
        },
        {
            "cmd": "AT+CREG?",
            "check": rb"CREG: 0,1"
        },
        {
            "cmd": "AT+CGATT?",
            "check": rb"CGATT: 1"
        },
        {
            "cmd": "AT+CMGF?",
            "check": rb"CMGF: 0"
        }
    ]

    for i in range(retry_count):
        for j in range(check_list.__len__()):
            cmd = check_list[j]["cmd"]
            check = check_list[j]["check"]
            resp = execute_at_command(serial_obj, cmd)
            logger.debug(f"command: {cmd}")
            logger.debug(f"response: {resp}")
            if not re.search(check, resp):
                logger.fatal(f"check failed in round {i}")
                time.sleep(1.5)
                break
            logger.info(f"check {j} passed")
            time.sleep(0.5)
        else:
            logger.info(f"all checks passed in round {i}")
            serial_obj.reset_input_buffer()
            serial_obj.flush()
            return True
    serial_obj.reset_input_buffer()
    serial_obj.flush()
    return False


def update_netkeeper_password():
    serial_port = find_serial_port("Quectel USB AT Port")
    try:
        ser = serial.Serial(serial_port, 9600)
        if not ser.port:
            raise SerialException("the serial port is incorrect")
    except SerialException as e:
        # 无法打开串口
        logger.fatal(f"failed to open serial port. information: {e}")
        exit(1)

    while netkeeper_password_update_flag:
        ser.reset_input_buffer()
        ser.flush()
        if is_ready(ser):
            # retry
            # to do
            sms_submit_obj = SMSSubmit(netkeeper_addr_smsc_addr, netkeeper_addr, netkeeper_password_query_msg)
            cmd = f"AT+CMGS={sms_submit_obj.to_unicode_hex_tpdu().__len__() // 2}"

            ser.reset_input_buffer()
            ser.flush()
            ser.write(f"{cmd}\r".encode())
            ser.readline()
            ser.write(sms_submit_obj.to_unicode_hex().encode())
            ser.write("\x1A".encode())

            # 发送完毕 检查结果
            ser.readline().strip()
            resp = ser.readline().strip()
            logger.debug(f"command: {cmd}")
            logger.debug(f"command: {sms_submit_obj.to_unicode_hex()}")
            logger.debug(f"response: {resp}")
            if b"ERROR" not in resp:
                # success
                retry_count_receive_sms = 60
                sms_id = -1
                for i in range(retry_count_receive_sms):
                    if ser.in_waiting > 0:
                        resp = ser.readline().strip()
                        logger.debug(f"response: {resp}")
                        # check data if sms was received
                        check = rb"CMTI: \"ME\",(\d+)"
                        match = re.search(check, resp)
                        if match:
                            sms_id = match.groups(0)[0].decode()
                            logger.info(f"sms received. sms id: {sms_id}")
                            # got sms id
                            break
                    time.sleep(0.5)

                if sms_id == -1:
                    logger.warning(f"no sms received. sleep for 5 minutes, then retry")
                    time.sleep(5 * 60)
                    continue
                # read sms by sms id
                cmd = f"AT+CMGR={sms_id}"
                resp = execute_at_command(ser, cmd, True, False)
                logger.debug(f"command: {cmd}")
                logger.debug(f"response: {resp}")
                # check = rb"CMGR: (\d+),.*,(\d+)$"
                # match = re.search(check, resp)
                # stat, tpduLen = match.groups(0)[0].decode(), match.groups(0)[1].decode()
                resp = ser.readline().strip()
                logger.debug(f"response: {resp}")
                sms_pdu_string = resp.decode()
                sms_delivery_obj = SMSDelivery(sms_pdu_string)
                sms_content = sms_delivery_obj.get_user_data_string()

                check = r"(\d{6})[^\d]+([\d\s\-:]+)"
                match = re.search(check, sms_content)
                global netkeeper_password
                global netkeeper_password_expiry_time
                netkeeper_password, netkeeper_password_expiry_time = match.groups(0)[0], math.ceil(time.mktime(time.strptime(match.groups(0)[1], '%Y-%m-%d %H:%M:%S')))
                logger.debug(f"sms content: {sms_content}")
                """
                SMSCAddrLen = int.from_bytes(msg[0:1])
                SMSCAddrType = msg[1:2]
                SMSCAddr = msg[2:SMSCAddrLen + 1]
                TP_FIRST_OCTET = msg[SMSCAddrLen + 1:SMSCAddrLen + 2]
                TP_OA_LEN = int.from_bytes(msg[SMSCAddrLen + 2:SMSCAddrLen + 3])
                TP_OA_TYPE = msg[SMSCAddrLen + 3:SMSCAddrLen + 4]
                TP_OA_ADDR = msg[SMSCAddrLen + 4:SMSCAddrLen + ((TP_OA_LEN + 1) // 2)]
                """

                # delete sms
                cmd = f"AT+CMGD={sms_id}"
                resp = execute_at_command(ser, cmd)
                logger.debug(f"command: {cmd}")
                logger.debug(f"response: {resp}")
                current_time = math.ceil(time.time())
                sleep_time = netkeeper_password_expiry_time - current_time + 2 * 60  # 到期2分钟后刷新密码
                if sleep_time < 0:  # 如果暂时没有更新 1分钟后重试
                    logger.warning(f"invalid sleep time")
                    sleep_time = 60
                    logger.info(f"sleep for {sleep_time} seconds")

                logger.info(f"sleep for {sleep_time} seconds")
                time.sleep(sleep_time)
            else:
                logger.fatal("failed to send sms")
                exit(1)
        else:
            logger.fatal("check failed")
            exit(1)


app = Flask(__name__)


@app.route('/get_password')
def get_password():
    global netkeeper_password
    return netkeeper_password


if __name__ == '__main__':
    update_thread = threading.Thread(daemon=True, target=update_netkeeper_password)
    update_thread.start()

    app.run(host='127.0.0.1', port=8080)


"""
接收单段短信
09 1Byte SMSC地址信息长度
91 1Byte SMSC地址格式
64000339511111F0
64000339541902F0 8Byte (SMSC地址信息长度 - 1Byte) SMSC地址
24 1Byte 基本参数
09 1Byte 回复地址字数
A1 1Byte 回复地址格式
01563900F5 5Byte(回复地址字数) 回复地址
00 1Byte 协议标识
08 1Byte 用户信息编码方式
42302091900423 7Byte 时间戳
66 1Byte 消息总长度
5C0A656C...... 消息
"""
"""
发送单段短信
08 1Byte SMSC地址信息长度
91 1Byte SMSC地址格式 //1001 0001
683143141802F0 7Byte (SMSC地址信息长度 - 1Byte) SMSC地址
11 1Byte 基本参数
00
0B 1Byte 被叫地址字数（按数字算)
91
6801563900F5 6Byte 被叫号码
00 1Byte TP-PI
08 1Byte 用户信息编码方式
00
04 2Byte 消息总长度
006D006D 消息
"""
"""
接收分段短信
08 1Byte SMSC地址信息长度
91 1Byte SMSC地址格式
683147523800F1 7Byte (SMSC地址信息长度 - 1Byte) SMSC地址
64 1Byte 基本参数
05 1Byte 回复地址字数
A1  回复地址格式
0180F6 3Byte(回复地址字数) 回复地址
00 1Byte 协议标识
08 1Byte 用户信息编码方式
42209212300423 7Byte 时间戳
12 1Byte 消息总长度
05 1Byte 消息头长度（不包含自身）
// 消息头参数[]
00 1Byte 消息头参数类型
03 1Byte 消息头参数长度
90 1Byte 消息标识号
02 1Byte 分段总数
02 1Byte 分段序号
30104E2D...... 消息
"""


