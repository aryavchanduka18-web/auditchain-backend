import re as _re

_SAFE_FILENAME = _re.compile(r'^[a-zA-Z0-9_\-\.]+$')

def validate_sol_file(file) -> tuple:
    """
    Validate uploaded file is a .sol file under 500KB with a safe filename.
    Returns (is_valid, error_message).
    Resets file pointer after reading.
    """
    filename = file.filename if hasattr(file, 'filename') else ""

    # Reject empty or unsafe filenames (path traversal prevention)
    if not filename or not _SAFE_FILENAME.match(filename):
        return False, "Invalid filename. Use only letters, numbers, hyphens, and underscores."

    if not filename.lower().endswith('.sol'):
        return False, "Only .sol files are accepted."

    content = file.read()
    file.seek(0)

    if len(content) > 500_000:
        return False, "File exceeds 500KB limit."

    # Reject empty files
    if len(content) == 0:
        return False, "File is empty."

    return True, ""
