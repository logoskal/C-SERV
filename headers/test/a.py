import os
import re

def rename_files_in_directory():
    # Get the current working directory
    directory_path = os.getcwd()

    # List all files in the directory
    for filename in os.listdir(directory_path):
        # Check if the file contains " - Copy" with an optional number in parentheses at the end
        match = re.search(r"(.*) - Copy.*\((\d+)\)(\.\w+)$", filename, re.IGNORECASE)
        if match:
            # Extract the base name (everything before last " - Copy"), the copy number, and the extension
            base_name = match.group(1)
            copy_number = match.group(2)
            extension = match.group(3)
            
            # Create the new file name with page number
            new_filename = f"{base_name}_page_{copy_number}{extension}"
            
            # Get the full file path
            old_file_path = os.path.join(directory_path, filename)
            new_file_path = os.path.join(directory_path, new_filename)
            
            # Rename the file
            os.rename(old_file_path, new_file_path)
            print(f"Renamed: {filename} -> {new_filename}")

# Run the function
rename_files_in_directory()
