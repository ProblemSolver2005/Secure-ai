import logging
import re

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render

from .ai_service import ask_grok, redact_sensitive_data
from .forms import AIQuestionForm, IncidentForm
from .models import Incident

logger = logging.getLogger(__name__)


@login_required
def dashboard(request):
    incidents = Incident.objects.all()
    context = {
        "total": incidents.count(),
        "open_count": incidents.exclude(status="Resolved").count(),
        "high_count": incidents.filter(
            severity__in=["High", "Critical"]
        ).exclude(status="Resolved").count(),
        "resolved_count": incidents.filter(status="Resolved").count(),
        "recent": incidents[:6],
        "severity_data": list(
            incidents.values("severity").annotate(count=Count("id")).order_by("severity")
        ),
    }
    return render(request, "assistant/dashboard.html", context)


@login_required
def ai_assistant(request):
    answer = None

    if request.method == "POST":
        form = AIQuestionForm(request.POST)
        if form.is_valid():
            answer, error = ask_grok(form.cleaned_data["question"])
            if error:
                messages.error(request, error)
    else:
        form = AIQuestionForm()

    return render(
        request,
        "assistant/ai_assistant.html",
        {"form": form, "answer": answer},
    )


@login_required
def incident_list(request):
    incidents = Incident.objects.all()
    status = request.GET.get("status", "")
    severity = request.GET.get("severity", "")
    search = request.GET.get("q", "").strip()

    if status:
        incidents = incidents.filter(status=status)
    if severity:
        incidents = incidents.filter(severity=severity)
    if search:
        incidents = incidents.filter(title__icontains=search) | incidents.filter(
            description__icontains=search
        )

    return render(
        request,
        "assistant/incident_list.html",
        {
            "incidents": incidents.distinct(),
            "status_filter": status,
            "severity_filter": severity,
            "q": search,
        },
    )


@login_required
def incident_create(request):
    if request.method == "POST":
        form = IncidentForm(request.POST)
        if form.is_valid():
            incident = form.save(commit=False)
            incident.created_by = request.user
            incident.save()
            messages.success(request, "Incident created successfully.")
            return redirect("incident_detail", pk=incident.pk)
    else:
        form = IncidentForm()

    return render(
        request,
        "assistant/incident_form.html",
        {"form": form, "heading": "Create incident"},
    )


@login_required
def incident_detail(request, pk):
    incident = get_object_or_404(Incident, pk=pk)
    return render(request, "assistant/incident_detail.html", {"incident": incident})


@login_required
def incident_update(request, pk):
    incident = get_object_or_404(Incident, pk=pk)

    if request.method == "POST":
        form = IncidentForm(request.POST, instance=incident)
        if form.is_valid():
            form.save()
            status = request.POST.get("status")
            if status in dict(Incident.STATUSES):
                incident.status = status
                incident.save(update_fields=["status", "updated_at"])
            messages.success(request, "Incident updated.")
            return redirect("incident_detail", pk=incident.pk)
    else:
        form = IncidentForm(instance=incident)

    return render(
        request,
        "assistant/incident_form.html",
        {"form": form, "heading": "Edit incident", "incident": incident},
    )


# Common indicators seen in Linux, Windows, web server, and application logs.
FAILED_PATTERNS = [
    r"\bstatus\s*=\s*(?:failed|failure|denied|blocked|unauthorized)\b",
    r"\b(?:failed|failure|unsuccessful)\s+(?:password|login|logon|authentication|auth|sign[\s_-]?in)\b",
    r"\b(?:login|logon|authentication|auth|sign[\s_-]?in)\s+(?:failed|failure|denied|unsuccessful)\b",
    r"\binvalid\s+(?:password|credential|username|user|token)\b",
    r"\b(?:bad|incorrect|wrong)\s+(?:password|credential)s?\b",
    r"\bunknown\s+(?:user|username|account)\b",
    r"\baccess\s+denied\b|\bpermission\s+denied\b",
    r"\bunauthori[sz]ed\b|\bforbidden\b",
    r"\bHTTP/[0-9.]+\s+(?:401|403)\b",
    r"\b(?:eventid|event\s*id)\s*[:= ]\s*4625\b",
    r"\b(?:invalid_password|authentication_failure|login_failed)\b",
]

SUCCESS_PATTERNS = [
    r"\bstatus\s*=\s*(?:success|successful|succeeded|accepted|allowed)\b",
    r"\b(?:successful|successfully)\s+(?:login|logon|authentication|auth|sign[\s_-]?in)\b",
    r"\b(?:login|logon|authentication|auth|sign[\s_-]?in)\s+(?:success|successful|succeeded)\b",
    r"\baccepted\s+(?:password|publickey|public key)\b",
    r"\buser\s+authenticated\b|\bauthentication\s+succeeded\b",
    r"\bHTTP/[0-9.]+\s+2[0-9]{2}\b",
    r"\b(?:eventid|event\s*id)\s*[:= ]\s*4624\b",
]

IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


def _matches_any(line, patterns):
    return any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns)


def _is_failed_event(line):
    return _matches_any(line, FAILED_PATTERNS)


def _is_success_event(line):
    # If a line has conflicting indicators, count it as failed, not successful.
    return not _is_failed_event(line) and _matches_any(line, SUCCESS_PATTERNS)


def _extract_ipv4_addresses(text):
    found = set()
    for candidate in IP_PATTERN.findall(text):
        octets = candidate.split(".")
        if all(0 <= int(octet) <= 255 for octet in octets):
            found.add(candidate)
    return sorted(found)


@login_required
def analyze_logs(request):
    result = None

    if request.method == "POST":
        uploaded = request.FILES.get("log_file")

        if not uploaded:
            messages.error(request, "Choose a log file first.")
        elif uploaded.size > 1_000_000:
            messages.error(request, "For this demo, log files must be smaller than 1 MB.")
        elif not uploaded.name.lower().endswith((".log", ".txt", ".csv")):
            messages.error(request, "Upload a .log, .txt, or .csv file.")
        else:
            try:
                raw = uploaded.read().decode("utf-8", errors="replace")
                lines = [line for line in raw.splitlines() if line.strip()]

                failed_lines = [line for line in lines if _is_failed_event(line)]
                successful_lines = [line for line in lines if _is_success_event(line)]
                unique_ips = _extract_ipv4_addresses(raw)

                # Keep the excerpt bounded before sending it to the AI provider.
                excerpt = "\n".join(lines[:200])

                # Redact before external processing. If the helper fails, report a
                # useful error rather than silently sending the unredacted content.
                sanitized_excerpt = redact_sensitive_data(excerpt)
                if not isinstance(sanitized_excerpt, str):
                    raise TypeError("redact_sensitive_data() did not return text")

                prompt = f"""
You are a security log analysis assistant. Analyze the log excerpt below.
The format may be Linux, Windows, web server, application, database, firewall,
or custom. Do not claim an attack is proven without evidence.

Locally calculated indicators (pattern-based estimates):
- Non-empty log lines: {len(lines)}
- Lines matching common failed or denied indicators: {len(failed_lines)}
- Lines matching common successful indicators: {len(successful_lines)}
- Distinct IPv4 addresses detected: {len(unique_ips)}

Please:
1. Identify the likely log type, or say unknown/custom if unclear.
2. Explain important errors, warnings, failed/denied events, and successful events.
3. Highlight repeated failures and unusual sequences.
4. Give practical, safe investigation steps.
5. Separate observed facts from possibilities; do not invent events.
6. Use simple headings and bullet points. Avoid Markdown tables.
7. Explain that automated counts are approximate because log formats vary.

Sanitized log excerpt:
{sanitized_excerpt}
"""

                answer, error = ask_grok(prompt)

                result = {
                    "lines": len(lines),
                    "failed": len(failed_lines),
                    "successful": len(successful_lines),
                    "ip_count": len(unique_ips),
                    "answer": answer if not error else None,
                }

                if error:
                    messages.error(request, error)

            except Exception as exc:
                logger.exception("Log file processing failed")
                messages.error(
                    request,
                    f"Log processing error: {type(exc).__name__}: {exc}",
                )

    return render(request, "assistant/analyze_logs.html", {"result": result})
