"""
Attack Graph Construction Module
Builds an evidence-backed directed attack/provenance graph.
Supported Node Types: email, domain, ip, page, action
Supported Node Statuses: critical, warning, clean, neutral
Supported Edge Keys: from, to, label

Strictly degrades gracefully on benign emails without fabricating malicious C2
or speculative exfiltration infrastructure.
"""

from typing import Dict, List, Any, Optional


def build_attack_graph(
    subject: str,
    sender_domain: str,
    origin_ip: Optional[str] = None,
    relay_hops: Optional[List[Dict[str, Any]]] = None,
    analyzed_urls: Optional[List[Dict[str, Any]]] = None,
    detected_intents: Optional[List[str]] = None,
    threat_score: int = 0,
    auth_status: str = "PASSED",
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Construct a directed graph connecting email provenance to delivery infrastructure,
    embedded resources, and evidenced threat actions.
    """
    nodes = []
    edges = []
    seen_nodes = set()

    def add_node(node_id: str, label: str, sublabel: str, node_type: str, status: str):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "sublabel": sublabel,
                "type": node_type,
                "status": status,
            })

    # 1. Root Email Node
    email_id = "node_email"
    email_label = subject if subject else "Email Message"
    email_status = "critical" if threat_score >= 70 else ("warning" if threat_score >= 40 else ("clean" if threat_score == 0 else "neutral"))
    add_node(email_id, email_label, "Target Artifact", "email", email_status)

    # 2. Sender Domain Node
    if sender_domain:
        domain_id = f"domain_{sender_domain}"
        domain_status = "critical" if auth_status == "FAILED" else ("warning" if auth_status == "PARTIAL" else "clean")
        add_node(domain_id, sender_domain, "Sender Domain", "domain", domain_status)
        edges.append({
            "from": email_id,
            "to": domain_id,
            "label": "From Domain",
        })

        # 3. Origin IP Node
        if origin_ip:
            ip_id = f"ip_{origin_ip}"
            ip_status = "warning" if threat_score >= 40 else ("clean" if threat_score == 0 else "neutral")
            add_node(ip_id, origin_ip, "Originating Relay", "ip", ip_status)
            edges.append({
                "from": domain_id,
                "to": ip_id,
                "label": "Relayed Via",
            })

    # 4. Embedded URL Nodes
    analyzed_urls = analyzed_urls or []
    for idx, u in enumerate(analyzed_urls[:5]):  # Cap at top 5 URLs to keep graph legible
        url_str = u.get("url") if isinstance(u, dict) else getattr(u, "url", "")
        url_domain = u.get("domain") if isinstance(u, dict) else getattr(u, "domain", "")
        u_score = u.get("threatScore", 0) if isinstance(u, dict) else getattr(u, "threatScore", 0)

        if url_str:
            url_node_id = f"url_{idx}"
            url_status = "critical" if u_score >= 70 else ("warning" if u_score >= 30 else "clean")
            add_node(url_node_id, url_str, f"Risk Score {u_score}", "page", url_status)
            edges.append({
                "from": email_id,
                "to": url_node_id,
                "label": "Embedded Link",
            })

            # Link page to its hosting domain
            if url_domain and url_domain != "unknown":
                target_dom_id = f"domain_{url_domain}"
                dom_status = "warning" if u_score >= 70 else "neutral"
                add_node(target_dom_id, url_domain, "Hosting Domain", "domain", dom_status)
                edges.append({
                    "from": url_node_id,
                    "to": target_dom_id,
                    "label": "Hosted On",
                })

            # 5. Evidenced Action Nodes (only if supported by content analysis)
            detected_intents = detected_intents or []
            if "Credential Harvesting" in detected_intents:
                action_id = "action_harvest"
                add_node(action_id, "Harvest Credentials", "Observed Intent", "action", "critical")
                edges.append({
                    "from": url_node_id,
                    "to": action_id,
                    "label": "Submits To",
                })
            elif "Financial Solicitation" in detected_intents:
                action_id = "action_payment"
                add_node(action_id, "Payment Redirection", "Observed Intent", "action", "critical")
                edges.append({
                    "from": url_node_id,
                    "to": action_id,
                    "label": "Submits To",
                })

    return {
        "nodes": nodes,
        "edges": edges,
    }
