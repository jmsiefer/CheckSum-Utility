import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox
import xml.etree.ElementTree as ET
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
import zlib  # For CRC32

def file_hash(filepath, method):
    """Generate a hash for a file based on the specified method."""
    hash_func = hashlib.new(method)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def file_crc32(filepath):
    """Generate a CRC32 checksum for a file."""
    buf_size = 65536  # Read in chunks of 64kb
    crc32 = 0
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(buf_size)
            if not data:
                break
            crc32 = zlib.crc32(data, crc32)
    return format(crc32 & 0xFFFFFFFF, '08x')

def find_files(root_folder, filename):
    """Recursively search for files matching filename within root_folder."""
    for root, dirs, files in os.walk(root_folder):
        if filename in files:
            return os.path.join(root, filename)
    return None

def verify_checksums(folder_path, checksum_file_path):
    """Verify files against the checksum data and generate a detailed report."""
    mismatches = []
    detailed_report = []
    total_files_checked = 0
    total_matched = 0
    try:
        tree = ET.parse(checksum_file_path)
        root = tree.getroot()
        for file_element in root.findall('.//file'):
            total_files_checked += 1
            filename = file_element.find('.//name').text
            file_path = find_files(folder_path, filename)
            if file_path:
                file_info = os.stat(file_path)
                file_size = file_info.st_size
                file_md5 = file_hash(file_path, 'md5')
                file_sha1 = file_hash(file_path, 'sha1')
                file_crc = file_crc32(file_path)
                
                expected_size = int(file_element.find('.//size').text)
                expected_md5 = file_element.find('.//md5').text
                expected_sha1 = file_element.find('.//sha1').text
                expected_crc = file_element.find('.//crc32').text
                
                size_check = file_size == expected_size
                md5_check = file_md5 == expected_md5
                sha1_check = file_sha1 == expected_sha1
                crc_check = file_crc == expected_crc
                
                if size_check and md5_check and sha1_check and crc_check:
                    total_matched += 1
                    file_data = f"Filename: {filename}\nPath: {file_path}\nStatus: Match\n\n"
                else:
                    mismatches.append(filename)
                    file_data = (f"Filename: {filename}\nPath: {file_path}\n"
                                 f"Size Check: {'Passed' if size_check else 'Failed'}\n"
                                 f"MD5 Check: {'Passed' if md5_check else 'Failed'}\n"
                                 f"SHA1 Check: {'Passed' if sha1_check else 'Failed'}\n"
                                 f"CRC32 Check: {'Passed' if crc_check else 'Failed'}\n"
                                 f"Status: Mismatch\n\n")
            else:
                mismatches.append(filename)
                file_data = f"Filename: {filename}\nPath: File not found\nStatus: File Missing\n\n"
            detailed_report.append(file_data)
        results = f"Total files checked: {total_files_checked}\nMatched: {total_matched}\nMismatches: {len(mismatches)}\n\n{''.join(detailed_report)}"
    except Exception as e:
        results = f"Error during verification: {str(e)}"
    return results

def start_verification():
    folder = folder_path.get()
    checksum = checksum_file_path.get()
    results = verify_checksums(folder, checksum)
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, results)
    messagebox.showinfo("Verification Complete", "Checksum verification has been completed.")

def save_to_pdf():
    """Save the results to a PDF file."""
    results = result_text.get("1.0", tk.END)
    if results.strip():
        filename = filedialog.asksaveasfilename(defaultextension=".pdf")
        if filename:
            doc = SimpleDocTemplate(filename, pagesize=letter)
            styles = getSampleStyleSheet()
            flowables = [Paragraph("Checksum Detailed Report", styles['Title']), Spacer(1, 12)]
            flowables += [Paragraph(line, styles['BodyText']) for line in results.split('\n') if line]
            doc.build(flowables)
            messagebox.showinfo("PDF Export", "Results exported to PDF successfully.")
    else:
        messagebox.showerror("PDF Export", "No results to export.")

root = tk.Tk()
root.title("Checksum Verifier")

top_frame = tk.Frame(root)
top_frame.pack(side=tk.TOP, fill=tk.X, expand=True)
left_frame = tk.Frame(top_frame)
left_frame.pack(side=tk.LEFT, fill=tk.Y, expand=True)
right_frame = tk.Frame(top_frame)
right_frame.pack(side=tk.RIGHT, fill=tk.Y, expand=True)

folder_path = tk.StringVar()
checksum_file_path = tk.StringVar()

tk.Label(left_frame, text="Select SD Content Folder:").pack()
folder_button = tk.Button(left_frame, text="Browse...", command=lambda: [folder_path.set(filedialog.askdirectory()), folder_label.config(text="OK")])
folder_button.pack()
folder_label = tk.Label(left_frame, text="")
folder_label.pack()

tk.Label(right_frame, text="Select the checksum file:").pack()
file_button = tk.Button(right_frame, text="Browse...", command=lambda: [checksum_file_path.set(filedialog.askopenfilename()), file_label.config(text="OK")])
file_button.pack()
file_label = tk.Label(right_frame, text="")
file_label.pack()

result_text = tk.Text(root, height=20, width=100)
result_text.pack(fill=tk.BOTH, expand=True)

button_frame = tk.Frame(root)
button_frame.pack(side=tk.BOTTOM, fill=tk.X, expand=True)
verify_button = tk.Button(button_frame, text="Verify Checksums", command=start_verification)
verify_button.pack(side=tk.LEFT, padx=10, pady=10)
export_button = tk.Button(button_frame, text="Export to PDF", command=save_to_pdf)
export_button.pack(side=tk.RIGHT, padx=10, pady=10)

scroll = tk.Scrollbar(root, command=result_text.yview)
scroll.pack(side=tk.RIGHT, fill=tk.Y)
result_text.config(yscrollcommand=scroll.set)

root.mainloop()
