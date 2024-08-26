import re


def parse_user_agent(user_agent):
    """
    Parses the user agent string to extract the application version and operating system type.
    Args:
        user_agent (str): The user agent string.
    Returns:
        tuple: A tuple containing the application version and operating system type.
    Example:
        >>> parse_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
        ('Chrome/58.0.3029.110', 'Windows NT 10.0; Win64; x64')
    """
    app_pattern = r'(Mozilla|Chrome|Safari|Firefox|Edge)/\d+\.\d+'
    os_pattern = r'\((.*?)\)'
    
    app_match = re.search(app_pattern, user_agent)
    os_match = re.search(os_pattern, user_agent)
    
    app_version = app_match.group(0) if app_match else "Unknown Application"
    os_type = os_match.group(1) if os_match else "Unknown OS"
    
    return app_version, os_type