import datetime as dt
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from dataclasses import dataclass
from typing import Dict, List
import xml.etree.ElementTree as ET

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


@dataclass
class Finding:
    host: str
    port: int
    protocol: str
    service: str
    risk: str
    cvss: float
    cve: str
    exploit_url: str
    recommendation: str


# Curated, defensive-oriented mapping for common exposed services.
RISK_DB: Dict[str, Dict[str, str]] = {
    "ftp": {
        "risk": "High",
        "cvss": "9.8",
        "cve": "CVE-2011-2523",
        "exploit_url": "https://www.exploit-db.com/exploits/49757",
        "recommendation": "Disable anonymous FTP, patch server software, and restrict access.",
    },
    "ssh": {
        "risk": "Medium",
        "cvss": "5.3",
        "cve": "CVE-2018-15473",
        "exploit_url": "https://www.exploit-db.com/exploits/45233",
        "recommendation": "Disable password auth where possible and enforce key-based access.",
    },
    "telnet": {
        "risk": "Critical",
        "cvss": "10.0",
        "cve": "CVE-2020-10188",
        "exploit_url": "https://www.exploit-db.com/exploits/48577",
        "recommendation": "Remove Telnet and migrate to encrypted remote access (SSH).",
    },
    "rdp": {
        "risk": "High",
        "cvss": "9.8",
        "cve": "CVE-2019-0708",
        "exploit_url": "https://www.exploit-db.com/exploits/47176",
        "recommendation": "Patch RDP services, enforce NLA, and restrict RDP exposure.",
    },
    "smb": {
        "risk": "Critical",
        "cvss": "10.0",
        "cve": "CVE-2017-0144",
        "exploit_url": "https://www.exploit-db.com/exploits/42031",
        "recommendation": "Patch SMB, disable SMBv1, and limit internal network exposure.",
    },
    "http": {
        "risk": "Medium",
        "cvss": "7.5",
        "cve": "CVE-2021-41773",
        "exploit_url": "https://www.exploit-db.com/exploits/50406",
        "recommendation": "Patch web servers, enforce TLS, and run web app hardening checks.",
    },
}


def parse_nmap_xml(path: str) -> List[Finding]:
    findings: List[Finding] = []
    tree = ET.parse(path)
    root = tree.getroot()

    for host in root.findall("host"):
        host_addr = host.find("address")
        host_ip = host_addr.attrib.get("addr", "unknown") if host_addr is not None else "unknown"
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            service_el = port.find("service")
            service_name = service_el.attrib.get("name", "unknown").lower() if service_el is not None else "unknown"
            mapping = RISK_DB.get(
                service_name,
                {
                    "risk": "Low",
                    "cvss": "0.0",
                    "cve": "N/A",
                    "exploit_url": "N/A",
                    "recommendation": "Review exposure and validate necessity of this open service.",
                },
            )

            findings.append(
                Finding(
                    host=host_ip,
                    port=int(port.attrib.get("portid", "0")),
                    protocol=port.attrib.get("protocol", "tcp"),
                    service=service_name,
                    risk=mapping["risk"],
                    cvss=float(mapping["cvss"]),
                    cve=mapping["cve"],
                    exploit_url=mapping["exploit_url"],
                    recommendation=mapping["recommendation"],
                )
            )

    return findings


def build_pdf_report(path: str, findings: List[Finding]) -> None:
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    title = "Internal Network Risk Assessment Report"
    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(f"Generated: {dt.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", styles["Normal"]))
    elements.append(Spacer(1, 12))

    summary = f"Total findings: {len(findings)}"
    elements.append(Paragraph(summary, styles["Heading3"]))
    elements.append(Spacer(1, 8))

    data = [["Host", "Port", "Service", "Risk", "CVSS", "CVE", "Exploit Link"]]
    for f in findings:
        data.append([f.host, f"{f.port}/{f.protocol}", f.service, f.risk, f"{f.cvss:.1f}", f.cve, f.exploit_url])

    table = Table(data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )

    elements.append(table)
    elements.append(Spacer(1, 14))
    elements.append(Paragraph("Recommendations", styles["Heading2"]))

    for f in findings:
        elements.append(
            Paragraph(
                f"<b>{f.host}:{f.port} ({f.service})</b> - {f.recommendation}",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 5))

    doc.build(elements)


class ScannerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Internal Network Scanner (Nmap XML Analyzer)")
        self.root.geometry("1050x600")
        self.findings: List[Finding] = []

        header = tk.Label(
            root,
            text="Authorized Use Only: Import Nmap XML and generate risk-focused PDF reports",
            font=("Arial", 12, "bold"),
            fg="#0B3D91",
        )
        header.pack(pady=10)

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=8)

        import_btn = tk.Button(btn_frame, text="Import Nmap XML", command=self.import_xml, width=20)
        import_btn.grid(row=0, column=0, padx=6)

        export_btn = tk.Button(btn_frame, text="Export PDF Report", command=self.export_pdf, width=20)
        export_btn.grid(row=0, column=1, padx=6)

        cols = ("host", "port", "service", "risk", "cvss", "cve", "exploit")
        self.tree = ttk.Treeview(root, columns=cols, show="headings", height=20)

        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=130)

        self.tree.column("exploit", width=280)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def import_xml(self):
        path = filedialog.askopenfilename(filetypes=[("Nmap XML", "*.xml")])
        if not path:
            return
        try:
            self.findings = parse_nmap_xml(path)
            self.refresh_table()
            messagebox.showinfo("Loaded", f"Loaded {len(self.findings)} findings from XML.")
        except Exception as exc:
            messagebox.showerror("Parse Error", f"Could not parse XML: {exc}")

    def refresh_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        for f in sorted(self.findings, key=lambda x: (-x.cvss, x.host, x.port)):
            self.tree.insert(
                "",
                "end",
                values=(f.host, f"{f.port}/{f.protocol}", f.service, f.risk, f"{f.cvss:.1f}", f.cve, f.exploit_url),
            )

    def export_pdf(self):
        if not self.findings:
            messagebox.showwarning("No Data", "Import an XML scan first.")
            return

        output = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if not output:
            return

        try:
            build_pdf_report(output, self.findings)
            messagebox.showinfo("Success", f"PDF report saved to {output}")
        except Exception as exc:
            messagebox.showerror("Export Error", f"Failed to generate report: {exc}")


if __name__ == "__main__":
    app = tk.Tk()
    ScannerGUI(app)
    app.mainloop()
