def validate_sol_file(file) -> tuple:
    """
    Validate uploaded file is a .sol file under 500KB.
    Returns (is_valid, error_message).
    Resets file pointer after reading.
    """
    filename = file.filename if hasattr(file, 'filename') else ""

    if not filename.lower().endswith('.sol'):
        return False, "Only .sol files are accepted."

    content = file.read()
    file.seek(0)

    if len(content) > 500_000:
        return False, "File exceeds 500KB limit."

    return True, ""
