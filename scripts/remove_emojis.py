import os
import re

# Regex for emojis
EMOJI_PATTERN = re.compile(
    "["
    "\U0001F300-\U0001F9FF]"  # Miscellaneous Symbols and Pictographs, Emoticons, Transport and Map Symbols, Supplemental Symbols and Pictographs
    "|[\u2600-\u26FF]"       # Miscellaneous Symbols
    "|[\u2700-\u27BF]"       # Dingbats
    "|[\u2300-\u23FF]"       # Miscellaneous Technical
    "|[\u1F600-\u1F64F]"     # Emoticons
    "|[\u2B50]"              # Star
    "|[\u2122]"              # Trademark
    "|[\u2139]"              # Information
    "|[\u231A]"              # Watch
    "|[\u231B]"              # Hourglass
    "|[\u23E9-\u23EC]"       # Rewind
    "|[\u23F0]"              # Alarm clock
    "|[\u23F3]"              # Hourglass
    "|[\u25AA-\u25AB]"       # Square
    "|[\u25FB-\u25FE]"       # Square
    "|[\u2600-\u26FE]"       # Misc
    "|[\u2702-\u27B0]"       # Dingbats
    "|[\u2934-\u2935]"       # Arrows
    "|[\u2B05-\u2B07]"       # Arrows
    "|[\u2B1B-\u2B1C]"       # Square
    "|[\u2B50]"              # Star
    "|[\u3030]"              # Wavy dash
    "|[\u303D]"              # Variation Selector
    "|[\u3297]"              # Circled Ideograph Congratulation
    "|[\u3299]"              # Secret
    "]",
    re.UNICODE
)

def remove_emojis(text):
    return EMOJI_PATTERN.sub("", text)

def process_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        new_content = remove_emojis(content)
        
        if content != new_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            return True
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
    return False

def main():
    root_dir = "."
    exclude_dirs = {'.git', 'node_modules', 'target', 'venv', '__pycache__'}
    processed_count = 0
    total_files = 0
    
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            total_files += 1
            filepath = os.path.join(root, file)
            if process_file(filepath):
                processed_count += 1
                print(f"Removed emojis from: {filepath}")

    print(f"Finished. Total files scanned: {total_files}. Files modified: {processed_count}")

if __name__ == "__main__":
    main()
