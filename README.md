
# Checksum Verifier

A Python script with a Tkinter-based GUI for verifying files against their checksums using MD5, SHA1, and CRC32 methods. It allows users to select a folder and a checksum XML file, verify the files, and export the detailed verification results to a PDF.

## Features

- **Checksum Verification**: Supports MD5, SHA1, and CRC32 checks for files.
- **File Searching**: Recursively searches for files within a selected folder.
- **Detailed Reports**: Generates a detailed report of the verification process, including matched and mismatched files.
- **Export to PDF**: Easily export the verification results to a PDF file for record-keeping.
- **User-Friendly Interface**: Simple GUI built with Tkinter for selecting folders, checksum files, and viewing results.

## Requirements

- Python 3.x
- `tkinter` (usually included with Python)
- `reportlab` library for PDF generation
- XML-formatted checksum file for verification

To install the `reportlab` library, run:
```bash
pip install reportlab
```

## Usage

1. **Run the script**:
   ```bash
   python CheckSum_V2.2.py
   ```

2. **Select the Folder**: Click "Browse..." to select the folder containing the files to verify.

3. **Select the Checksum File**: Click "Browse..." to select the XML file containing the checksum data.

4. **Verify Checksums**: Click "Verify Checksums" to begin the verification process. The results will be displayed in the text area.

5. **Export to PDF**: After verification, click "Export to PDF" to save the results as a PDF file.

## XML Checksum File Structure

The XML file should have the following structure:

```xml
<checksums>
    <file>
        <name>example.txt</name>
        <size>12345</size>
        <md5>abcdef1234567890abcdef1234567890</md5>
        <sha1>abcdef1234567890abcdef1234567890abcdef12</sha1>
        <crc32>12345678</crc32>
    </file>
    <!-- More file entries -->
</checksums>
```

## Example

```xml
<checksums>
    <file>
        <name>document.pdf</name>
        <size>2048</size>
        <md5>9e107d9d372bb6826bd81d3542a419d6</md5>
        <sha1>2fd4e1c67a2d28fced849ee1bb76e7391b93eb12</sha1>
        <crc32>414fa339</crc32>
    </file>
</checksums>
```

## Notes

- Ensure that the XML checksum file is accurate and matches the files in the selected folder.
- The script reads files in chunks to optimize memory usage during hash calculation.
- Use the `Export to PDF` feature to save a copy of the verification report for your records.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
