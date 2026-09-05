import urllib.parse
import re

def validate_target(target: str) -> bool:
    """
    Validates the target format.
    Authorized IPs and domains restriction was removed per user request.
    The user is responsible for testing only authorized infrastructure.
    """
    if not target:
        return False

    # Reject shell injection characters
    dangerous = [";", "&", "|", "`", "$", "\n", "\r", "<", ">", "\x00"]
    if any(c in target for c in dangerous):
        return False
        
    # Basic URL/IP validation
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme and parsed.netloc:
        return True
        
    # Simple IP/domain regex fallback
    domain_regex = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?$')
    ip_regex = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$')
    
    if domain_regex.match(target) or ip_regex.match(target):
        return True
        
    return False


def sanitize_target(target: str) -> str:
    """
    Sanitizes target string and raises ValueError if dangerous shell characters are found.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target cannot be empty.")

    cleaned = target.strip().replace("\x00", "")
    dangerous = [";", "&", "|", "`", "$", "\n", "\r", "<", ">"]
    for char in dangerous:
        if char in cleaned:
            raise ValueError(f"Prohibited character '{char}' detected in target: {cleaned}")

    if not validate_target(cleaned):
        raise ValueError(f"Invalid target format: {cleaned}")

    return cleaned
