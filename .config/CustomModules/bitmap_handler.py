"""
Bitmap Handler Module

Provides bitmap-based permission management for API keys.
"""


class BitmapHandler:
    """
    Handles permission bitmaps for API key authorization.

    Each permission is represented by a bit position, allowing efficient
    storage and checking of multiple permissions in a single integer.
    """

    def __init__(self, key_list: list[str], logger=None):
        """
        Initialize the bitmap handler.

        Args:
            key_list: List of permission names in order (bit position = index)
            logger: Logger instance for debug/error logging (optional)
        """
        self.key_list = key_list
        self.logger = logger

    def check_key_in_bitkey(self, permission_name: str, bitmap: int) -> bool:
        """
        Check if a specific permission is enabled in a bitmap.

        Args:
            permission_name: The permission to check (e.g., "generate-secret")
            bitmap: The permission bitmap value

        Returns:
            bool: True if the permission is enabled, False otherwise
        """
        if permission_name not in self.key_list:
            if self.logger:
                self.logger.warning(f"Unknown permission: {permission_name}")
            return False

        bit_position = self.key_list.index(permission_name)
        bit_value = 1 << bit_position
        return (bitmap & bit_value) != 0
