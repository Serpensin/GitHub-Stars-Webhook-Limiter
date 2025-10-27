import logging
from typing import Dict, List, Union


class BitmapHandler:
    def __init__(self, keys: List[str], logger=None):
        """
        Initialize the BitmapHandler with a list of keys.

        Args:
            keys (List[str]): A list of keys to initialize the bitmap.
            A maximum of 64 keys can be provided.
            logger: Optional logger instance. If not provided, creates its own.

        Raises:
            ValueError: If more than 64 keys are provided.
        """
        # Initialize logger
        if logger is None:
            self.logger = logging.getLogger("custommodules.bitmaphandler")
        else:
            self.logger = logger.getChild("custommodules.bitmaphandler")

        if len(keys) > 64:
            raise ValueError(
                "Warning: You are trying to initialize with more than 64 keys. "
                "This may exceed the limit for bit manipulation."
            )

        # Generate the bitmap dictionary dynamically
        self.bitmap: Dict[str, int] = {key: index for index, key in enumerate(keys)}
        self.key_list: List[str] = keys.copy()  # Store keys in a list for ordering

        self.logger.debug(f"BitmapHandler initialized with {len(keys)} permission keys")

    def get_bitkey(self, *args: str) -> int:
        """
        Converts a list of keys into a single bitkey.

        Args:
            *args (str): A variable number of keys to be converted to a bitkey.

        Returns:
            int: The bitkey representing the provided keys.

        Raises:
            KeyError: If any key is invalid (not in the bitmap).
        """
        bitkey = 0
        for key in args:
            if key in self.bitmap:
                bitkey |= 1 << self.bitmap[key]
            elif key is None or key == "":
                continue
            else:
                raise KeyError(f"Invalid key: {key}")
        return bitkey

    def check_key_in_bitkey(self, key: str, bitkey: int) -> bool:
        """
        Checks if a given key is present in the bitkey.

        Args:
            key (str): The key to check.
            bitkey (int): The bitkey in which to check for the key.

        Returns:
            bool: True if the key is present in the bitkey, False otherwise.
        """
        if key not in self.bitmap:
            return False
        return bool(bitkey & (1 << self.bitmap[key]))

    def get_active_keys(self, bitkey: int, single: bool = False) -> Union[str, List[str]]:
        """
        Retrieves the active keys from a bitkey.

        Args:
            bitkey (int): The bitkey from which to retrieve active keys.
            single (bool, optional): If True, returns the last active key as a string.
            If False, returns a list of active keys. Defaults to False.

        Returns:
            Union[str, List[str]]: The active keys in the bitkey.

        Raises:
            ValueError: If the bitkey is invalid (not within the valid range).
        """
        max_bitkey = (1 << len(self.bitmap)) - 1
        if bitkey < 0 or bitkey > max_bitkey:
            raise ValueError(f"Invalid bitkey: {bitkey}. It must be between 0 and {max_bitkey}.")

        active_keys = [
            key for key, bit_position in self.bitmap.items() if bitkey & (1 << bit_position)
        ]

        if single:
            return active_keys[-1] if active_keys else ""

        return active_keys

    def toggle_key_in_bitkey(self, key: str, bitkey: int, add: bool = True) -> int:
        """
        Adds or removes a given key from an existing bitkey based on the 'add' parameter.

        Args:
            key (str): The key to add or remove.
            bitkey (int): The existing bitkey.
            add (bool, optional): If True, the key is added to the bitkey;
            if False, the key is removed. Defaults to True.

        Returns:
            int: The updated bitkey after the operation.

        Raises:
            KeyError: If the key is invalid (not in the bitmap).
        """
        if key not in self.bitmap:
            raise KeyError(f"Invalid key: {key}")

        # Add or remove the bit based on the 'add' flag
        if add:
            return bitkey | (1 << self.bitmap[key])
        else:
            return bitkey & ~(1 << self.bitmap[key])

    def invert_bitkey(self, bitkey: int) -> int:
        """
        Inverts all bits in the given bitkey.

        Args:
            bitkey (int): The bitkey to be inverted.

        Returns:
            int: The inverted bitkey.
        """
        max_bitkey = (1 << len(self.bitmap)) - 1
        return ~bitkey & max_bitkey

    def count_active_bits(self, bitkey: int) -> int:
        """
        Counts the number of active (set) bits in the bitkey.

        Args:
            bitkey (int): The bitkey for which to count active bits.

        Returns:
            int: The count of active bits in the bitkey.
        """
        return bin(bitkey).count("1")

    def compare_bitkeys(self, bitkey1: int, bitkey2: int) -> Dict[str, List[str]]:
        """
        Compares two bitkeys and returns a dictionary of differences.

        Args:
            bitkey1 (int): The first bitkey to compare.
            bitkey2 (int): The second bitkey to compare.

        Returns:
            Dict[str, List[str]]: A dictionary containing the common keys,
            keys only in the first bitkey, and keys only in the second bitkey.
        """
        common = bitkey1 & bitkey2
        only_in_1 = bitkey1 & ~bitkey2
        only_in_2 = bitkey2 & ~bitkey1

        return {
            "common_keys": self.get_active_keys(common),
            "only_in_bitkey1": self.get_active_keys(only_in_1),
            "only_in_bitkey2": self.get_active_keys(only_in_2),
        }

    def add_key(self, key: str):
        """
        Adds a new key to the bitmap.

        Args:
            key (str): The key to add.

        Raises:
            KeyError: If the key already exists in the bitmap.
        """
        if key in self.bitmap:
            raise KeyError(f"Key '{key}' already exists.")

        # Add the new key and update the bitmap and key_list
        self.bitmap[key] = len(self.bitmap)  # Assign the next available index
        self.key_list.append(key)  # Append the new key to the list

    def remove_key(self, key: str):
        """
        Removes a key from the bitmap.

        Args:
            key (str): The key to remove.

        Raises:
            KeyError: If the key does not exist in the bitmap.
        """
        if key not in self.bitmap:
            raise KeyError(f"Key '{key}' does not exist.")

        # Remove the key and reassign indices for the remaining keys
        index_to_remove = self.bitmap[key]
        del self.bitmap[key]

        # Reassign keys and their bit positions only if the key is not the last one
        if len(self.bitmap) > 0:
            for k in self.bitmap:
                if self.bitmap[k] > index_to_remove:
                    self.bitmap[k] -= 1

        self.key_list.remove(key)  # Remove from key list

    def get_keys(self) -> Dict[str, int]:
        """
        Returns the current bitmap dictionary.

        Returns:
            Dict[str, int]: The current bitmap dictionary mapping keys to their bit positions.
        """
        return self.bitmap
