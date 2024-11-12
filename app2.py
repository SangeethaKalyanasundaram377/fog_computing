def view_encrypted_file(file_path):
    try:
        with open(file_path, "rb") as encrypted_file:
            # Read the binary content of the encrypted file
            encrypted_data = encrypted_file.read()

            # Convert binary data to hexadecimal for better readability
            hex_data = encrypted_data.hex()
            
            # Print hex format in chunks for readability
            chunk_size = 32  # Number of hex characters per line
            for i in range(0, len(hex_data), chunk_size):
                print(hex_data[i:i + chunk_size])

    except Exception as e:
        print("Error reading the encrypted file:", e)

# Usage

view_encrypted_file("C:\\Users\\Sangeetha\\Desktop\\My Folder\\Downloads\\encrypted_file (11).ext")
#7b0a2020226d657373616765223a2022
#2766696c655f6b657927222c0a202022
#73756363657373223a2066616c73650a
#7d0a

