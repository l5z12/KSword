import os
import chardet

def detect_encoding(file_path):
    """Detect file encoding"""
    with open(file_path, 'rb') as f:
        # Read the first 10KB of data for encoding detection to improve accuracy.
        raw_data = f.read(10240)
        result = chardet.detect(raw_data)
        return result['encoding']

def convert_to_utf8(file_path):
    """Convert file to UTF-8 encoding."""
    try:
        # Detect current encoding
        encoding = detect_encoding(file_path)
        if not encoding:
            print(f"⚠️ Unable to detect the encoding of {file_path}, skipping processing")
            return False

        # Skip if already UTF-8.
        if encoding.lower() in ['utf-8', 'utf-8-sig']:
            print(f"ℹ️ {file_path} is already UTF-8 encoded, no conversion needed")
            return True

        # Read file content.
        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
            content = f.read()

        # Write as UTF-8 encoding (without BOM).
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        print(f"✅ Converted {file_path} from {encoding} to UTF-8")
        return True

    except Exception as e:
        print(f"❌ Error processing {file_path}: {str(e)}")
        return False

def main():
    # Get current directory
    current_dir = os.getcwd()
    print(f"📂 Processing directory: {current_dir}")

    # Filter to select only .h and .cpp files (excluding subfolders).
    for filename in os.listdir(current_dir):
        file_path = os.path.join(current_dir, filename)
        # Process only files, not folders.
        if os.path.isfile(file_path):
            # Check file extension
            if filename.lower().endswith(('.h', '.cpp')):
                convert_to_utf8(file_path)

    print("🎉 Processing complete")

if __name__ == "__main__":
    # Check if the chardet library is installed.
    try:
        import chardet
    except ImportError:
        print("❌ chardet library not found, please install first: pip install chardet")
        exit(1)

    main()
