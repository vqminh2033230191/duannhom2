from collections import Counter
import os
import pandas as pd
import zlib

# Thống nhất dùng chung thư mục samples/ với Bạn 2
SAMPLES_DIR = "samples"
OUTPUT_CSV = "dataset_ngram_features.csv"


def extract_hash_grams_from_file(file_path, n=4, chunk_size=8192, top_k=50):
  """Đọc trực tiếp dãy mã nhị phân (byte) của file .exe theo từng chunk,

  tạo N-grams và tối ưu bằng Hash-grams (crc32) để chống tràn RAM.
  """
  counts = Counter()
  buffer = bytearray()

  try:
    with open(file_path, "rb") as f:
      while True:
        chunk = f.read(chunk_size)
        if not chunk:
          break

        # Ghép buffer với chunk hiện tại để không bỏ sót N-gram ở ranh giới
        data = buffer + chunk

        # Cắt dãy byte thành các đoạn nhỏ liền kề (N-grams)
        for i in range(len(data) - n + 1):
          ngram = data[i : i + n]
          h_gram = zlib.crc32(ngram)
          counts[h_gram] += 1

        # Lưu lại (n - 1) byte cuối để nối tiếp cho chunk tiếp theo
        buffer = data[-(n - 1) :]

  except Exception as e:
    print(f"Lỗi khi đọc file {file_path}: {e}")
    return None

  return counts.most_common(top_k)


def main():
  dataset = []
  # Nhãn khớp với cấu trúc thư mục của Bạn 2: "clean" (0) và "malware" (1)
  labels_map = {"clean": 0, "malware": 1}

  print("[*] Bắt đầu quét thư mục mẫu để trích xuất N-grams & Hash-grams...")

  for label_str, label_val in labels_map.items():
    folder_path = os.path.join(SAMPLES_DIR, label_str)
    if not os.path.isdir(folder_path):
      print(f"[!] Không tìm thấy thư mục {folder_path}, vui lòng kiểm tra lại.")
      continue

    for filename in os.listdir(folder_path):
      file_path = os.path.join(folder_path, filename)
      if os.path.isfile(file_path):
        top_common = extract_hash_grams_from_file(file_path, n=4, top_k=50)
        if top_common:
          row = {"filename": filename, "label": label_val}
          for h_val, freq in top_common:
            row[f"hash_{h_val:08x}"] = freq
          dataset.append(row)
          print(f"  [+] Đã xử lý xong: {label_str}/{filename}")

  # Xuất kết quả ra file CSV để bàn giao cho đội ngũ Machine Learning
  if dataset:
    df = pd.DataFrame(dataset).fillna(0)
    df.to_csv(OUTPUT_CSV, index=False)
    print(
        f"\n[+] Hoàn thành xuất file đặc trưng N-grams ra: '{OUTPUT_CSV}' thành"
        " công!"
    )
  else:
    print(
        "[-] Chưa tìm thấy file mẫu nào trong thư mục samples/. Hãy thêm file"
        " vào nhé."
    )


if __name__ == "__main__":
  main()