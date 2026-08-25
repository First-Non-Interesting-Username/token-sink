"""CLI equivalents for the human-control surface (PLAN.md §17).

Non-interactive, automation-friendly. Each command maps 1:1 to a Controls
method so every UI state-changing action has an auditable CLI equivalent.
Wired via `build_cli()`; the application entrypoint (issue #20) supplies the
shared AuditLog/KillSwitch/Controls instances.
"""

from __future__ import annotations

import argparse
import json
import sys

from .controls import Controls


def build_parser(controls: Controls) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="system controls", description="Human-control surface")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("kill-switch", help="Engage global kill switch")
    sp.add_argument("--reason", default="")
    sp.add_argument("--actor", default="")

    pp = sub.add_parser("campaign-pause", help="Pause a campaign")
    pp.add_argument("campaign")
    pp.add_argument("--actor", default="")

    rp = sub.add_parser("campaign-resume", help="Resume a paused campaign")
    rp.add_argument("campaign")
    rp.add_argument("--actor", default="")

    tp = sub.add_parser("campaign-stop", help="Stop a campaign permanently")
    tp.add_argument("campaign")
    tp.add_argument("--actor", default="")

    cp = sub.add_parser("agent-cancel", help="Cancel an agent (propagates to subagents)")
    cp.add_argument("campaign")
    cp.add_argument("agent")
    cp.add_argument("--actor", default="")

    ep = sub.add_parser("agent-retry", help="Retry a failed/cancelled agent")
    ep.add_argument("campaign")
    ep.add_argument("agent")
    ep.add_argument("--actor", default="")

    qp = sub.add_parser("finding-quarantine", help="Quarantine a finding (preserves history)")
    qp.add_argument("campaign")
    qp.add_argument("finding")
    qp.add_argument("--reason", default="")
    qp.add_argument("--actor", default="")

    ap = sub.add_parser("approval-decide", help="Grant or deny a pending approval")
    ap.add_argument("approval_id")
    ap.add_argument("--grant", action="store_true")
    ap.add_argument("--deny", dest="grant", action="store_false")
    ap.add_argument("--reason", default="")
    ap.add_argument("--actor", default="")

    sub.add_parser("approvals-pending", help="List pending approvals")

    sub.add_parser("audit-verify", help="Verify audit log hash chain integrity")
    return p


def run_cli(argv: list[str], controls: Controls, out=sys.stdout) -> int:
    args = build_parser(controls).parse_args(argv)
    try:
        if args.cmd == "kill-switch":
            n = controls.activate_kill_switch(actor=args.actor, reason=args.reason)
            print(json.dumps({"status": "engaged", "tasks_cancelled": n}), file=out)
        elif args.cmd == "campaign-pause":
            controls.pause_campaign(args.campaign, actor=args.actor)
            print(json.dumps({"status": "paused"}), file=out)
        elif args.cmd == "campaign-resume":
            controls.resume_campaign(args.campaign, actor=args.actor)
            print(json.dumps({"status": "running"}), file=out)
        elif args.cmd == "campaign-stop":
            controls.stop_campaign(args.campaign, actor=args.actor)
            print(json.dumps({"status": "stopped"}), file=out)
        elif args.cmd == "agent-cancel":
            controls.cancel_agent(args.campaign, args.agent, actor=args.actor)
            print(json.dumps({"status": "cancelled"}), file=out)
        elif args.cmd == "agent-retry":
            task = controls.retry_agent(args.campaign, args.agent, actor=args.actor)
            print(json.dumps({"status": "queued", "task": task}), file=out)
        elif args.cmd == "finding-quarantine":
            controls.quarantine_finding(
                args.campaign, args.finding, actor=args.actor, reason=args.reason
            )
            print(json.dumps({"status": "quarantined"}), file=out)
        elif args.cmd == "approval-decide":
            req = controls.decide_approval(
                args.approval_id,
                granted=args.grant,
                decided_by=args.actor,
                decision_reason=args.reason,
            )
            print(json.dumps({"approval": req.id, "status": req.status}), file=out)
        elif args.cmd == "approvals-pending":
            rows = [
                {"id": r.id, "action": r.action, "subject": r.subject}
                for r in controls.pending_approvals()
            ]
            print(json.dumps(rows), file=out)
        elif args.cmd == "audit-verify":
            ok = controls.audit.verify()
            print(json.dumps({"chain_intact": ok}), file=out)
            return 0 if ok else 1
    except Exception as exc:  # surface control errors as nonzero exit, not traceback
        print(json.dumps({"error": str(exc)}), file=out)
        return 2
    return 0
