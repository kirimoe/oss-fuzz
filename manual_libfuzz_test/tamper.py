import os
import sys
import random

def append_random_bytes(filepath, num_bytes):
    """
    Appends a specified number of random bytes to the end of a file.

    Args:
        filepath (str): The path to the file to modify.
        num_bytes (int): The number of random bytes to append.
    """
    try:
        # Open the file in append binary mode
        # 'ab' ensures that we write to the end of the file,
        # and 'b' means binary mode, so we write raw bytes.
        with open(filepath, 'ab') as f:
            print(f"Appending {num_bytes} random bytes to '{filepath}'...")

            # Generate random bytes
            # os.urandom(num_bytes) generates cryptographically strong random bytes.
            # This is generally preferred for fuzzing inputs as it's less predictable
            # than other random number generators.
            random_data = os.urandom(num_bytes)

            # Write the generated random data to the file
            f.write(random_data)

        print(f"Successfully appended {num_bytes} bytes. New file size: {os.path.getsize(filepath)} bytes.")

    except FileNotFoundError:
        print(f"Error: The file '{filepath}' was not found.")
    except IOError as e:
        print(f"Error writing to file '{filepath}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    # Check if the correct number of arguments are provided
    if len(sys.argv) < 2:
        print("Usage: python append_random.py <yarc_file_path> [num_bytes_to_append]")
        print("  <yarc_file_path>: Path to the YARA compiled rule file.")
        print("  [num_bytes_to_append]: Optional. Number of random bytes to append. Defaults to 1024.")
        sys.exit(1)

    file_to_modify = sys.argv[1]
    num_bytes_str = sys.argv[2] if len(sys.argv) > 2 else "1024" # Default to 1024 bytes

    try:
        num_bytes = int(num_bytes_str)
        if num_bytes < 0:
            print("Error: Number of bytes to append cannot be negative.")
            sys.exit(1)
    except ValueError:
        print(f"Error: '{num_bytes_str}' is not a valid number for bytes to append.")
        sys.exit(1)

    append_random_bytes(file_to_modify, num_bytes)
