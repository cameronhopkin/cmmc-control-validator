#!/usr/bin/env python3
"""
CMMC Control Validator - NIST 800-171 Control Definitions
NIST SP 800-171 Rev 2 control requirements.

Author: Cameron Hopkin
License: MIT
"""
from typing import Dict, List

# NIST 800-171 Rev 2 Basic Security Requirements (subset)
NIST_800_171_CONTROLS: Dict[str, Dict] = {
    # Access Control
    "3.1.1": {
        "family": "AC",
        "requirement": "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).",
        "discussion": "Access control policies control access between active entities or subjects and passive entities or objects in systems. Access enforcement mechanisms can be employed at the application and service level to provide increased information security.",
        "cmmc_mapping": "AC.L2-3.1.1"
    },
    "3.1.2": {
        "family": "AC",
        "requirement": "Limit system access to the types of transactions and functions that authorized users are permitted to execute.",
        "discussion": "Organizations may choose to define access privileges or other attributes by account, by type of account, or a combination of both.",
        "cmmc_mapping": "AC.L2-3.1.2"
    },
    "3.1.3": {
        "family": "AC",
        "requirement": "Control the flow of CUI in accordance with approved authorizations.",
        "discussion": "Information flow control regulates where information can travel within a system and between systems.",
        "cmmc_mapping": "AC.L2-3.1.3"
    },
    "3.1.5": {
        "family": "AC",
        "requirement": "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
        "discussion": "Organizations employ the principle of least privilege for specific duties and authorized accesses for users and processes.",
        "cmmc_mapping": "AC.L2-3.1.5"
    },
    "3.1.7": {
        "family": "AC",
        "requirement": "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.",
        "discussion": "Privileged functions include establishing system accounts, performing system integrity checks, conducting patching operations, or administering cryptographic key management activities.",
        "cmmc_mapping": "AC.L2-3.1.7"
    },

    # Audit and Accountability
    "3.3.1": {
        "family": "AU",
        "requirement": "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
        "discussion": "An event is any observable occurrence in a system, which includes unlawful or unauthorized system activity.",
        "cmmc_mapping": "AU.L2-3.3.1"
    },
    "3.3.2": {
        "family": "AU",
        "requirement": "Ensure that the actions of individual system users can be uniquely traced to those users so they can be held accountable for their actions.",
        "discussion": "This requirement ensures that the contents of the audit record include the information needed to link the audit event to the actions of an individual.",
        "cmmc_mapping": "AU.L2-3.3.2"
    },

    # Identification and Authentication
    "3.5.1": {
        "family": "IA",
        "requirement": "Identify system users, processes acting on behalf of users, and devices.",
        "discussion": "Common device identifiers include Media Access Control (MAC) addresses, Internet Protocol (IP) addresses, or device-unique token identifiers.",
        "cmmc_mapping": "IA.L2-3.5.1"
    },
    "3.5.2": {
        "family": "IA",
        "requirement": "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.",
        "discussion": "Individual authenticators include passwords, key cards, cryptographic devices, and one-time password devices.",
        "cmmc_mapping": "IA.L2-3.5.2"
    },
    "3.5.3": {
        "family": "IA",
        "requirement": "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.",
        "discussion": "Multifactor authentication requires the use of two or more different factors to achieve authentication.",
        "cmmc_mapping": "IA.L2-3.5.3"
    },

    # System and Communications Protection
    "3.13.1": {
        "family": "SC",
        "requirement": "Monitor, control, and protect communications (i.e., information transmitted or received by organizational systems) at the external boundaries and key internal boundaries of organizational systems.",
        "discussion": "Communications can be monitored, controlled, and protected at boundary components and by restricting or prohibiting interfaces in organizational systems.",
        "cmmc_mapping": "SC.L2-3.13.1"
    },
    "3.13.8": {
        "family": "SC",
        "requirement": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.",
        "discussion": "This requirement applies to internal and external networks and any system components that can transmit information.",
        "cmmc_mapping": "SC.L2-3.13.8"
    },
    "3.13.11": {
        "family": "SC",
        "requirement": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.",
        "discussion": "Cryptography can be employed to support many security solutions including the protection of controlled unclassified information.",
        "cmmc_mapping": "SC.L2-3.13.11"
    },
    "3.13.16": {
        "family": "SC",
        "requirement": "Protect the confidentiality of CUI at rest.",
        "discussion": "Information at rest refers to the state of information when it is not in process or in transit and is located on storage devices.",
        "cmmc_mapping": "SC.L2-3.13.16"
    },

    # System and Information Integrity
    "3.14.1": {
        "family": "SI",
        "requirement": "Identify, report, and correct system flaws in a timely manner.",
        "discussion": "Organizations identify systems affected by announced software and firmware flaws including potential vulnerabilities resulting from those flaws.",
        "cmmc_mapping": "SI.L2-3.14.1"
    },
    "3.14.2": {
        "family": "SI",
        "requirement": "Provide protection from malicious code at appropriate locations within organizational systems.",
        "discussion": "Designated locations include system entry and exit points which may include firewalls, remote-access servers, workstations, electronic mail servers, web servers, proxy servers, and notebook computers.",
        "cmmc_mapping": "SI.L2-3.14.2"
    },
    "3.14.6": {
        "family": "SI",
        "requirement": "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
        "discussion": "System monitoring includes external and internal monitoring. System monitoring can detect unauthorized use of organizational systems as well as attacks.",
        "cmmc_mapping": "SI.L2-3.14.6"
    },

    # Configuration Management
    "3.4.1": {
        "family": "CM",
        "requirement": "Establish and maintain baseline configurations and inventories of organizational systems (including hardware, software, firmware, and documentation) throughout the respective system development life cycles.",
        "discussion": "Baseline configurations are documented, formally reviewed, and agreed-upon specifications for systems or configuration items within those systems.",
        "cmmc_mapping": "CM.L2-3.4.1"
    },
    "3.4.2": {
        "family": "CM",
        "requirement": "Establish and enforce security configuration settings for information technology products employed in organizational systems.",
        "discussion": "Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture or functionality of the system.",
        "cmmc_mapping": "CM.L2-3.4.2"
    },
}


def get_control(control_id: str) -> Dict:
    """Get a specific NIST 800-171 control."""
    return NIST_800_171_CONTROLS.get(control_id)


def get_controls_by_family(family: str) -> List[Dict]:
    """Get all controls for a specific family."""
    return [
        {"id": k, **v}
        for k, v in NIST_800_171_CONTROLS.items()
        if v["family"] == family.upper()
    ]


def get_cmmc_mapping(nist_id: str) -> str:
    """Get CMMC practice ID for a NIST control."""
    control = NIST_800_171_CONTROLS.get(nist_id)
    return control.get("cmmc_mapping") if control else None
