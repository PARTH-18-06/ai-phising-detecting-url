from __future__ import annotations

from datetime import datetime
from statistics import mean
from typing import Any
from uuid import uuid4

from flask import Flask, jsonify, redirect, render_template, request, url_for

app = Flask(__name__)

LIVE_SESSIONS: dict[str, dict[str, Any]] = {}
ARCHIVED_SESSIONS: dict[str, dict[str, Any]] = {}


def now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def create_session(candidate_name: str, role: str) -> dict[str, Any]:
    session_id = uuid4().hex[:10]
    session = {
        "id": session_id,
        "candidate_name": candidate_name,
        "role": role,
        "created_at": now_iso(),
        "last_updated": now_iso(),
        "events": [],
        "alerts": [],
        "monitoring": {
            "eye_contact_samples": [],
            "noise_samples": [],
            "attention_samples": [],
            "multiple_people_count": 0,
            "tab_switch_count": 0,
            "copy_paste_count": 0,
            "left_camera_count": 0,
            "phone_detected_count": 0,
            "suspicious_sound_count": 0,
            "other_voice_count": 0,
            "low_visibility_count": 0,
        },
        "speech": {
            "filler_words": 0,
            "words_spoken": 0,
            "clarity_score": 70.0,
            "fluency_score": 70.0,
        },
        "technical": {
            "coding_score": 65.0,
            "aptitude_score": 65.0,
            "communication_score": 65.0,
            "hr_confidence": 65.0,
            "react_score": 65.0,
        },
    }
    LIVE_SESSIONS[session_id] = session
    return session


def add_alert(session: dict[str, Any], message: str, severity: str = "medium") -> None:
    alert = {
        "timestamp": now_iso(),
        "severity": severity,
        "message": message,
    }
    session["alerts"].append(alert)
    # Keep the alert list light for frontend polling
    if len(session["alerts"]) > 75:
        session["alerts"] = session["alerts"][-75:]


def add_event(session: dict[str, Any], event_type: str, payload: dict[str, Any]) -> None:
    event = {
        "timestamp": now_iso(),
        "type": event_type,
        "payload": payload,
    }
    session["events"].append(event)
    if len(session["events"]) > 800:
        session["events"] = session["events"][-800:]

    monitoring = session["monitoring"]

    if event_type == "attention_sample":
        eye_contact = float(payload.get("eye_contact", 0))
        noise = float(payload.get("noise_level", 0))
        attention = float(payload.get("attention_level", 0))
        monitoring["eye_contact_samples"].append(clamp(eye_contact))
        monitoring["noise_samples"].append(clamp(noise))
        monitoring["attention_samples"].append(clamp(attention))

        # Bound the arrays to avoid unbounded memory growth
        monitoring["eye_contact_samples"] = monitoring["eye_contact_samples"][-250:]
        monitoring["noise_samples"] = monitoring["noise_samples"][-250:]
        monitoring["attention_samples"] = monitoring["attention_samples"][-250:]

    elif event_type == "tab_switch":
        monitoring["tab_switch_count"] += 1
        add_alert(session, "Frequent screen switching detected", "high")

    elif event_type == "copy_paste":
        monitoring["copy_paste_count"] += 1
        add_alert(session, "Copy-paste action detected", "high")

    elif event_type == "left_camera":
        monitoring["left_camera_count"] += 1
        add_alert(session, "Candidate left camera frame", "high")

    elif event_type == "multiple_people":
        monitoring["multiple_people_count"] += 1
        add_alert(session, "Multiple people detected on camera", "critical")

    elif event_type == "mobile_phone":
        monitoring["phone_detected_count"] += 1
        add_alert(session, "Mobile phone usage suspected", "critical")

    elif event_type == "suspicious_sound":
        monitoring["suspicious_sound_count"] += 1
        add_alert(session, "Suspicious sound spike detected", "medium")

    elif event_type == "other_voice":
        monitoring["other_voice_count"] += 1
        add_alert(session, "Other voice activity detected", "high")

    elif event_type == "low_visibility":
        monitoring["low_visibility_count"] += 1
        add_alert(session, "Low visibility or dark room detected", "medium")

    elif event_type == "speech_metrics":
        speech = session["speech"]
        speech["filler_words"] += int(payload.get("filler_words", 0))
        speech["words_spoken"] += int(payload.get("words_spoken", 0))
        speech["clarity_score"] = clamp(float(payload.get("clarity_score", speech["clarity_score"])))
        speech["fluency_score"] = clamp(float(payload.get("fluency_score", speech["fluency_score"])))

    session["last_updated"] = now_iso()


def compute_scores(session: dict[str, Any]) -> dict[str, Any]:
    monitoring = session["monitoring"]
    technical = session["technical"]
    speech = session["speech"]

    eye_contact_avg = mean(monitoring["eye_contact_samples"]) if monitoring["eye_contact_samples"] else 65.0
    noise_avg = mean(monitoring["noise_samples"]) if monitoring["noise_samples"] else 30.0
    attention_avg = mean(monitoring["attention_samples"]) if monitoring["attention_samples"] else 68.0

    focus_score = clamp(
        (0.45 * eye_contact_avg)
        + (0.55 * attention_avg)
        - (monitoring["left_camera_count"] * 5.0)
        - (monitoring["tab_switch_count"] * 2.2)
    )

    confidence_score = clamp(
        (0.45 * technical["communication_score"])
        + (0.25 * technical["hr_confidence"])
        + (0.2 * speech["fluency_score"])
        + (0.1 * eye_contact_avg)
        - (speech["filler_words"] * 0.2)
    )

    integrity_penalty = (
        monitoring["multiple_people_count"] * 14
        + monitoring["copy_paste_count"] * 5
        + monitoring["tab_switch_count"] * 4
        + monitoring["phone_detected_count"] * 12
        + monitoring["other_voice_count"] * 6
    )
    integrity_score = clamp(100 - integrity_penalty)

    technical_score = clamp(
        0.35 * technical["coding_score"]
        + 0.2 * technical["aptitude_score"]
        + 0.25 * technical["communication_score"]
        + 0.2 * technical["hr_confidence"]
    )

    final_score = clamp(
        0.3 * focus_score + 0.25 * confidence_score + 0.25 * integrity_score + 0.2 * technical_score
    )

    if noise_avg < 33:
        noise_level = "Low"
    elif noise_avg < 66:
        noise_level = "Medium"
    else:
        noise_level = "High"

    if attention_avg >= 75:
        attention_level = "Excellent"
    elif attention_avg >= 58:
        attention_level = "Good"
    else:
        attention_level = "Needs Improvement"

    behavior_flags = [
        f"Left camera: {monitoring['left_camera_count']} time(s)",
        f"Multiple people: {monitoring['multiple_people_count']} alert(s)",
        f"Tab switches: {monitoring['tab_switch_count']}",
        f"Copy-paste: {monitoring['copy_paste_count']}",
        f"Phone usage: {monitoring['phone_detected_count']}",
        f"Other voices: {monitoring['other_voice_count']}",
    ]

    # Emotion approximation for hackathon demo based on combined signals
    stress_index = clamp((100 - confidence_score) * 0.45 + noise_avg * 0.35 + monitoring["tab_switch_count"] * 2.0)
    if stress_index >= 70:
        emotion_state = "High stress / nervous"
    elif stress_index >= 45:
        emotion_state = "Moderate stress"
    else:
        emotion_state = "Composed / confident"

    recommendations = []
    if technical["coding_score"] < 65:
        recommendations.append("DSA Foundation Sprint: arrays, graphs, DP, timed coding drills")
    if technical["communication_score"] < 65 or speech["fluency_score"] < 65:
        recommendations.append("Communication Booster: structured speaking, filler-word reduction, mock HR rounds")
    if technical["react_score"] < 65:
        recommendations.append("React Frontend Roadmap: components, state, hooks, mini projects")
    if technical["aptitude_score"] < 65:
        recommendations.append("Aptitude Mastery Plan: quant, logical reasoning, speed practice")
    if not recommendations:
        recommendations.append("Advanced mock interviews with pressure scenarios and leadership prompts")

    summary = (
        f"{session['candidate_name']} showed {attention_level.lower()} focus with {round(eye_contact_avg, 1)}% eye contact. "
        f"Integrity risk remained {'low' if integrity_score >= 80 else 'moderate/high'} with "
        f"{monitoring['tab_switch_count']} tab switches and {monitoring['copy_paste_count']} copy-paste events."
    )

    return {
        "focus_score": round(focus_score, 1),
        "confidence_score": round(confidence_score, 1),
        "integrity_score": round(integrity_score, 1),
        "technical_score": round(technical_score, 1),
        "final_score": round(final_score, 1),
        "eye_contact": round(eye_contact_avg, 1),
        "noise_level": noise_level,
        "attention_level": attention_level,
        "emotion_state": emotion_state,
        "behavior_flags": behavior_flags,
        "summary": summary,
        "recommendations": recommendations,
        "speech": {
            "filler_words": speech["filler_words"],
            "clarity_score": round(speech["clarity_score"], 1),
            "fluency_score": round(speech["fluency_score"], 1),
            "words_spoken": speech["words_spoken"],
        },
        "technical_breakdown": technical,
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/start", methods=["POST"])
def start_interview():
    candidate_name = (request.form.get("candidate_name") or "Candidate").strip()
    role = (request.form.get("role") or "Software Engineer").strip()
    session = create_session(candidate_name, role)
    return redirect(url_for("interview_room", session_id=session["id"]))


@app.route("/interview/<session_id>")
def interview_room(session_id: str):
    session = LIVE_SESSIONS.get(session_id)
    if not session:
        return redirect(url_for("home"))
    return render_template("interview.html", session=session)


@app.route("/api/session/<session_id>/event", methods=["POST"])
def ingest_event(session_id: str):
    session = LIVE_SESSIONS.get(session_id)
    if not session:
        return jsonify({"ok": False, "error": "Session not found"}), 404

    data = request.get_json(silent=True) or {}
    event_type = data.get("type", "unknown")
    payload = data.get("payload", {})
    add_event(session, event_type, payload)

    live_scores = compute_scores(session)
    return jsonify({"ok": True, "scores": live_scores, "recent_alerts": session["alerts"][-5:]})


@app.route("/api/session/<session_id>/technical", methods=["POST"])
def update_technical_scores(session_id: str):
    session = LIVE_SESSIONS.get(session_id)
    if not session:
        return jsonify({"ok": False, "error": "Session not found"}), 404

    data = request.get_json(silent=True) or {}
    technical = session["technical"]

    for key in ["coding_score", "aptitude_score", "communication_score", "hr_confidence", "react_score"]:
        if key in data:
            technical[key] = clamp(float(data[key]))

    session["last_updated"] = now_iso()
    return jsonify({"ok": True, "scores": compute_scores(session)})


@app.route("/api/session/<session_id>/live")
def live_snapshot(session_id: str):
    session = LIVE_SESSIONS.get(session_id)
    if not session:
        return jsonify({"ok": False, "error": "Session not found"}), 404

    return jsonify({
        "ok": True,
        "scores": compute_scores(session),
        "alerts": session["alerts"][-12:],
        "event_count": len(session["events"]),
        "candidate": {
            "name": session["candidate_name"],
            "role": session["role"],
            "started": session["created_at"],
        },
    })


@app.route("/api/session/<session_id>/complete", methods=["POST"])
def complete_session(session_id: str):
    session = LIVE_SESSIONS.get(session_id)
    if not session:
        return jsonify({"ok": False, "error": "Session not found"}), 404

    report = compute_scores(session)
    session["report"] = report
    session["completed_at"] = now_iso()

    ARCHIVED_SESSIONS[session_id] = session
    LIVE_SESSIONS.pop(session_id, None)

    return jsonify({"ok": True, "report_url": url_for("report", session_id=session_id)})


@app.route("/report/<session_id>")
def report(session_id: str):
    session = ARCHIVED_SESSIONS.get(session_id) or LIVE_SESSIONS.get(session_id)
    if not session:
        return redirect(url_for("home"))

    report_data = session.get("report") or compute_scores(session)
    return render_template("report.html", session=session, report=report_data)


@app.route("/dashboard")
def dashboard():
    sessions = []

    for sess in ARCHIVED_SESSIONS.values():
        scores = sess.get("report") or compute_scores(sess)
        sessions.append(
            {
                "id": sess["id"],
                "candidate_name": sess["candidate_name"],
                "role": sess["role"],
                "status": "Completed",
                "final_score": scores["final_score"],
                "integrity_score": scores["integrity_score"],
                "focus_score": scores["focus_score"],
                "flags": len([a for a in sess["alerts"] if a["severity"] in {"high", "critical"}]),
                "report": scores,
            }
        )

    for sess in LIVE_SESSIONS.values():
        scores = compute_scores(sess)
        sessions.append(
            {
                "id": sess["id"],
                "candidate_name": sess["candidate_name"],
                "role": sess["role"],
                "status": "Live",
                "final_score": scores["final_score"],
                "integrity_score": scores["integrity_score"],
                "focus_score": scores["focus_score"],
                "flags": len([a for a in sess["alerts"] if a["severity"] in {"high", "critical"}]),
                "report": scores,
            }
        )

    sessions.sort(key=lambda item: item["final_score"], reverse=True)
    return render_template("dashboard.html", sessions=sessions)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
