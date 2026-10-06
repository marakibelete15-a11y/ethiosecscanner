"""
Central Vocabulary and Allowed Values for EthioSec Scanner.

Single source of truth for severity levels, statuses, depth profiles,
verification methods, module keys, and report formats across the application.
"""

# Severity levels (Critical MUST be first-class across filters, sorting, and UI)
SEVERITY_VALUES = ("critical", "high", "medium", "low", "info")

# Finding lifecycle status
FINDING_STATUS_VALUES = ("open", "confirmed", "false_positive", "resolved")

# Scan execution status
SCAN_STATUS_VALUES = ("queued", "running", "completed", "failed", "cancelled")

# Scan depth profiles
SCAN_DEPTH_VALUES = ("quick", "standard", "deep")

# Target ownership verification methods
VERIFICATION_METHOD_VALUES = ("dns_txt", "meta_tag", "http_file")

# Finding confidence levels
CONFIDENCE_VALUES = ("low", "medium", "high", "certain")

# Report export formats
REPORT_FORMAT_VALUES = ("pdf", "html", "json")

# Module execution status inside scans.module_progress
MODULE_STATUS_VALUES = ("pending", "running", "done", "error")

# User account roles
USER_ROLE_VALUES = ("user", "admin")

# The 11 recognized scanner check modules
SCANNER_MODULE_KEYS = (
    "headers",
    "https",
    "cookies",
    "cors",
    "http_methods",
    "info_disclosure",
    "exposed_files",
    "sqli",
    "xss",
    "access_control",
    "auth_checks",
)
