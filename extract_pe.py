"""
BẠN 2 - Bóc tách thông tin file: PE Header & YARA
Chạy:  pip install pefile yara-python
       python extract_pe.py

Cấu trúc thư mục cần chuẩn bị:
    samples/
        clean/     <- file .exe sạch (lấy từ C:\\Windows\\System32, C:\\Program Files...)
        malware/   <- file .exe mã độc (lấy từ kho mẫu an toàn, xem hướng dẫn cuối file)
    rules.yar      <- tập luật YARA (file đi kèm)

Kết quả: dataset_pe.csv (bàn giao cho Bạn 4)
"""

import os
import csv
import math
import hashlib

import pefile

# NOTE: yara-python là thư viện riêng. Nếu chưa cài được, script vẫn chạy
# được phần còn lại (cột yara_matches sẽ để trống).
try:
    import yara
except ImportError:
    yara = None

SAMPLES_DIR = "samples"
RULES_FILE = "rules.yar"
OUTPUT_CSV = "dataset_pe.csv"

# NOTE: "API" = hàm hệ thống Windows mà chương trình gọi để nhờ hệ điều hành
# làm việc (tạo file, mở mạng, ghi vào bộ nhớ...). Mã độc hay dùng những hàm
# dưới đây nên đếm chúng làm "đặc trưng" để Bạn 4 huấn luyện mô hình.
# Lưu ý: file sạch cũng có thể dùng một vài hàm này, nên KHÔNG kết luận
# "có API này = mã độc". Chỉ dùng số lượng làm dữ liệu tham khảo.
SUSPICIOUS_APIS = {
    # Tiêm code vào tiến trình khác (process injection)
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
    "CreateRemoteThread", "NtUnmapViewOfSection", "SetThreadContext",
    # Tải file / kết nối mạng
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA",
    "InternetOpenUrlA", "WinHttpOpen",
    # Chạy chương trình khác
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA",
    # Tự khởi động cùng Windows (ghi Registry)
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
    # Ghi lại phím bấm
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    # Chống phân tích / chống debug
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    # Mã hóa (ransomware hay dùng)
    "CryptEncrypt", "CryptAcquireContextA",
    # Nạp hàm động (che giấu API thật đang dùng)
    "LoadLibraryA", "GetProcAddress",
}


def compute_hashes(path):
    """Tính MD5 và SHA-256 của file.

    NOTE: Hash là "dấu vân tay" của file. Chỉ cần 1 byte khác là hash khác hẳn.
    Dùng để tra cứu nhanh trên VirusTotal (dán SHA-256 vào ô search).
    Đọc từng khối 8KB để không tốn RAM với file lớn.
    """
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def entropy(data):
    """Tính entropy (độ 'hỗn loạn') của dữ liệu, thang 0-8.

    NOTE: Entropy cao (> 7.0) thường nghĩa là dữ liệu bị nén/mã hóa,
    tức file có thể bị PACK (đóng gói để giấu code thật). Đây là dấu hiệu
    khá hay gặp ở mã độc. File sạch thường ~5-6.5.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def extract_pe_features(path):
    """Đọc thông tin bên trong file .exe bằng pefile."""
    # NOTE: PE (Portable Executable) là định dạng file .exe/.dll của Windows.
    # Bên trong gồm: Header (thông tin chung), Section (các "ngăn" chứa code,
    # dữ liệu), Import table (danh sách hàm hệ thống mà file gọi).
    pe = pefile.PE(path)

    # --- Các section ---
    # NOTE: Section thường thấy: .text (code), .data (dữ liệu), .rsrc (tài nguyên).
    # Tên lạ như UPX0, .aspack, .themida = file bị packer đóng gói.
    section_names, entropies = [], []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode(errors="ignore")
        section_names.append(name)
        entropies.append(entropy(s.get_data()))

    # --- Các hàm hệ thống (import) ---
    all_imports, suspicious_found = [], set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:  # NOTE: có hàm import theo số thứ tự (không có tên) -> bỏ qua
                    fn = imp.name.decode(errors="ignore")
                    all_imports.append(fn)
                    if fn in SUSPICIOUS_APIS:
                        suspicious_found.add(fn)

    features = {
        "num_sections": len(pe.sections),
        "section_names": "|".join(section_names),
        "max_section_entropy": round(max(entropies), 3) if entropies else 0,
        "avg_section_entropy": round(sum(entropies) / len(entropies), 3) if entropies else 0,
        "num_imports": len(all_imports),
        "num_suspicious_apis": len(suspicious_found),
        "suspicious_apis": "|".join(sorted(suspicious_found)),
        # NOTE: Entry point = địa chỉ nơi chương trình bắt đầu chạy.
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_size": pe.OPTIONAL_HEADER.SizeOfImage,
        # NOTE: 0x14c = 32-bit, 0x8664 = 64-bit
        "machine": hex(pe.FILE_HEADER.Machine),
        # NOTE: Timestamp = thời điểm compile. Mã độc hay bị làm giả (=0 hoặc năm lạ).
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "is_dll": int(pe.is_dll()),
    }
    pe.close()
    return features


def load_yara_rules():
    if yara is None or not os.path.exists(RULES_FILE):
        return None
    return yara.compile(filepath=RULES_FILE)


def main():
    rules = load_yara_rules()
    rows = []

    # NOTE: Tên thư mục (clean / malware) chính là NHÃN (label) của mẫu.
    # Bạn 4 sẽ dùng cột label để huấn luyện mô hình phân loại.
    for label in ("clean", "malware"):
        folder = os.path.join(SAMPLES_DIR, label)
        if not os.path.isdir(folder):
            print(f"[!] Không thấy thư mục {folder}, bỏ qua")
            continue

        for fname in os.listdir(folder):
            path = os.path.join(folder, fname)
            if not os.path.isfile(path):
                continue

            row = {"file_name": fname, "label": label}
            row["md5"], row["sha256"] = compute_hashes(path)

            try:
                row.update(extract_pe_features(path))
            except pefile.PEFormatError:
                # NOTE: File hỏng hoặc không phải PE hợp lệ -> ghi lại để biết, không làm sập script
                print(f"[!] {fname}: không phải file PE hợp lệ, bỏ qua")
                continue

            row["yara_matches"] = ""
            if rules:
                row["yara_matches"] = "|".join(m.rule for m in rules.match(path))

            rows.append(row)
            print(f"[+] {label}/{fname}")

    if not rows:
        print("Không có mẫu nào. Kiểm tra lại thư mục samples/")
        return

    # Gom tất cả cột (các file có thể thiếu cột nếu lỗi) rồi ghi CSV
    fieldnames = list(rows[0].keys())
    # NOTE: utf-8-sig để mở bằng Excel không bị lỗi font
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nXong! Đã ghi {len(rows)} mẫu vào {OUTPUT_CSV}")


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------------
# HƯỚNG DẪN THU THẬP MẪU (làm thủ công, code không tự làm được)
#
# File SẠCH: copy vài chục file .exe từ C:\Windows\System32 (notepad.exe,
#            calc.exe, mspaint.exe...) hoặc từ C:\Program Files.
#
# File MÃ ĐỘC: tải từ kho mẫu nghiên cứu như MalwareBazaar (bazaar.abuse.ch)
#            hoặc theZoo (GitHub). QUY TẮC AN TOÀN BẮT BUỘC:
#   1. Chỉ tải và xử lý trong máy ảo (VirtualBox/VMware), tắt chia sẻ
#      thư mục và clipboard với máy thật, nên ngắt mạng.
#   2. TUYỆT ĐỐI KHÔNG double-click chạy các file trong samples/malware.
#      Script này chỉ ĐỌC cấu trúc file (phân tích tĩnh), không thực thi.
#   3. Nên để file nén có mật khẩu (thường là "infected") cho tới lúc cần dùng.
#   4. Tắt hoặc loại trừ thư mục mẫu khỏi Windows Defender, nếu không nó sẽ xóa file.
# ---------------------------------------------------------------------------