// NOTE: YARA là "công cụ tìm mẫu". Mỗi rule = 1 luật gồm:
//   strings   : các chuỗi/byte cần tìm trong file
//   condition : điều kiện để tính là "khớp" (match)
// import "pe" cho phép hỏi thông tin cấu trúc PE (tên section, số section...).
// Các luật dưới đây chỉ là dấu hiệu NGHI NGỜ, không phải kết luận chắc chắn.

import "pe"

// NOTE: uint16(0) == 0x5A4D nghĩa là 2 byte đầu file là "MZ" - chữ ký
// của mọi file .exe/.dll trên Windows.

rule Is_PE_File
{
    meta:
        description = "File có chữ ký PE hợp lệ (MZ header)"
    condition:
        uint16(0) == 0x5A4D
}

rule Packed_UPX
{
    meta:
        description = "File bị đóng gói bằng UPX (section tên UPX0/UPX1)"
        note = "UPX cũng dùng cho phần mềm sạch, chỉ là dấu hiệu tham khảo"
    condition:
        uint16(0) == 0x5A4D and
        for any s in pe.sections : ( s.name == "UPX0" or s.name == "UPX1" )
}

rule Process_Injection_APIs
{
    meta:
        description = "Có đủ bộ hàm thường dùng để tiêm code vào tiến trình khác"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Downloader_Behavior
{
    meta:
        description = "Có hàm tải file từ internet và hàm chạy chương trình"
    strings:
        $dl1 = "URLDownloadToFile" ascii
        $dl2 = "InternetOpenUrl" ascii
        $ex1 = "WinExec" ascii
        $ex2 = "ShellExecute" ascii
    condition:
        uint16(0) == 0x5A4D and
        (any of ($dl*)) and (any of ($ex*))
}

rule Persistence_Registry_Run
{
    meta:
        description = "Nhắc tới khóa Registry Run (cách mã độc tự khởi động cùng Windows)"
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $set = "RegSetValueEx" ascii
    condition:
        uint16(0) == 0x5A4D and all of them
}

rule Anti_Debug
{
    meta:
        description = "Có hàm kiểm tra xem có đang bị debug/phân tích không"
    strings:
        $a = "IsDebuggerPresent" ascii
        $b = "CheckRemoteDebuggerPresent" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}