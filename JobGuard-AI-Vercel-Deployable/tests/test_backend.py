"""Comprehensive automated backend test suite for JobGuard AI (including Multilingual Call Recording Scam Detection)."""
from __future__ import annotations

import io
import json
import math
import struct
import unittest
import wave
from docx import Document
from fastapi.testclient import TestClient

from backend.auth import init_auth_database, issue_auth_token
from backend.main import app
from backend.schemas import EvidenceStatus, RiskLevel
from backend.security import redact_sensitive_info
from backend.url_inspector import inspect_url_structurally


def _make_sample_wav_bytes(duration_sec: float = 0.5, sample_rate: int = 8000) -> bytes:
    buf = io.BytesIO()
    n_frames = int(duration_sec * sample_rate)
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        frames = b"".join(
            struct.pack("<h", int(8000 * math.sin(2 * math.pi * 440 * i / sample_rate)))
            for i in range(n_frames)
        )
        wf.writeframes(frames)
    return buf.getvalue()


class TestJobGuardBackend(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        init_auth_database()
        cls.client = TestClient(app)

    def test_01_health_and_frontend_served(self) -> None:
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["service"], "JobGuard AI")
        self.assertTrue(resp.json()["call_scam_detection"])
        root = self.client.get("/")
        self.assertEqual(root.status_code, 200)
        self.assertIn("JobGuard AI", root.text)
        app_js_resp = self.client.get("/app.js")
        self.assertEqual(app_js_resp.status_code, 200)
        self.assertIn("Call Recording Scam Detector", app_js_resp.text)
        css_resp = self.client.get("/styles.css")
        self.assertEqual(css_resp.status_code, 200)

    def test_02_advance_fee_english_scam_high_risk(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": "Company: Apex Global\nRole: Data Entry\nPay ₹999 registration fee to confirm your job today. Selected without interview."
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["risk_level"], RiskLevel.HIGH.value)
        self.assertEqual(len(data["categories"]), 7)
        self.assertGreaterEqual(data["suspicious_indicator_count"], 2)

    def test_03_hinglish_registration_fee_detected(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={"text": "Job ke liye pehle ₹1500 registration fees jama karo aur bina interview ke direct joining pao."},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["detected_language"], "hinglish")
        self.assertEqual(data["risk_level"], RiskLevel.HIGH.value)

    def test_04_hindi_security_deposit_detected(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={"text": "बिना इंटरव्यू के नौकरी पाने के लिए ₹2,000 सिक्योरिटी डिपॉजिट दें।"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["detected_language"], "hi")
        self.assertEqual(data["risk_level"], RiskLevel.HIGH.value)

    def test_05_anti_fraud_disclaimer_not_false_positive(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": (
                    "Company: Infosys Limited\nRole: Software Engineer\nLocation: Bengaluru\n"
                    "Apply at https://www.infosys.com/careers/ or email careers@infosys.com.\n"
                    "Important: Never pay any registration fee during recruitment. Infosys does not charge any fee."
                )
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["risk_level"], RiskLevel.LOW.value)
        self.assertEqual(data["suspicious_indicator_count"], 0)

    def test_06_urgent_word_alone_not_high_risk(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": (
                    "Company: Razorpay\nRole: Backend Engineer\nLocation: Bengaluru\n"
                    "Urgent reminder: please confirm your technical interview slot via recruiting@razorpay.com."
                )
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertNotEqual(data["risk_level"], RiskLevel.HIGH.value)
        self.assertEqual(data["risk_level"], RiskLevel.LOW.value)

    def test_07_unknown_company_marked_unverified_not_fraud(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": (
                    "Company: Sunrise Agritech Solutions\nRole: Field Analyst\nSalary: 6 LPA\n"
                    "Location: Lucknow\nApply via careers@sunriseagritech.in for technical interview."
                )
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["risk_level"], RiskLevel.LOW.value)
        emp_cat = data["categories"][0]
        self.assertEqual(emp_cat["category_name"], "Employer Identity")
        self.assertEqual(emp_cat["overall_status"], EvidenceStatus.UNVERIFIED.value)

    def test_08_fake_infosys_career_portal_impersonation(self) -> None:
        res = inspect_url_structurally("https://infosys.careers-verification.xyz/apply")
        self.assertEqual(res.risk_level, RiskLevel.HIGH)
        self.assertEqual(res.registrable_domain, "careers-verification.xyz")
        self.assertEqual(res.impersonated_brand, "INFOSYS")

    def test_09_url_shortener_raw_ip_punycode_and_dangerous_scheme(self) -> None:
        ip_res = inspect_url_structurally("http://192.168.1.50/hr-login")
        self.assertTrue(ip_res.is_ip_address)
        self.assertGreaterEqual(ip_res.risk_index, 55)

        puny = inspect_url_structurally("https://xn--infsys-cwa.com/careers")
        self.assertTrue(puny.has_punycode_or_idn)

        js_res = inspect_url_structurally("javascript:alert(1)")
        self.assertEqual(js_res.risk_level, RiskLevel.HIGH)

    def test_10_email_domain_mismatch_and_personal_email(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": "Company: Tata Consultancy Services (TCS)\nRole: Developer\nSend resume to tcs.hr.desk2026@gmail.com"
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        cat4 = data["categories"][3]
        self.assertEqual(cat4["category_name"], "Email and Domain Alignment")
        self.assertEqual(cat4["overall_status"], EvidenceStatus.SUSPICIOUS_SIGNAL.value)

    def test_11_cross_document_consistency_conflict(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={
                "text": "Company: Infosys Limited\nRole: Systems Engineer\nSalary: 5 LPA\nLocation: Bengaluru",
                "secondary_text": "Company: GlobalTech Staffing\nRole: Data Entry Operator\nSalary: ₹15,000 per month\nLocation: Noida",
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        cat7 = data["categories"][6]
        self.assertEqual(cat7["overall_status"], EvidenceStatus.INCONSISTENT.value)
        self.assertGreaterEqual(data["inconsistent_check_count"], 1)

    def test_12_unavailable_providers_never_marked_confirmed(self) -> None:
        r = self.client.post(
            "/api/verify",
            json={"text": "Company: Razorpay\nRole: Backend Engineer\nRequisition ID: RZP-100"},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        cat2 = data["categories"][1]
        self.assertEqual(cat2["category_name"], "Vacancy and Requisition Verification")
        statuses = [rec["status"] for rec in cat2["records"]]
        self.assertIn(EvidenceStatus.CHECK_UNAVAILABLE.value, statuses)
        self.assertNotIn(EvidenceStatus.CONFIRMED_BY_SOURCE.value, statuses)

    def test_13_pre_analysis_10_field_extraction_and_edits(self) -> None:
        r = self.client.post(
            "/api/extract",
            json={"text": "Company: Zoho\nRole: Software Developer\nSalary: 8 LPA\nLocation: Chennai"},
        )
        self.assertEqual(r.status_code, 200)
        ext = r.json()
        self.assertEqual(ext["employer"]["status"], "extracted")
        self.assertEqual(ext["requisition_id"]["status"], "missing")
        self.assertIsNone(ext["requisition_id"]["value"])

        v = self.client.post(
            "/api/verify",
            json={
                "text": "Company: Zoho\nRole: Software Developer",
                "edited_fields": {"requisition_id": "ZOHO-2026-42"},
            },
        )
        self.assertEqual(v.status_code, 200)
        self.assertEqual(v.json()["extracted_data"]["requisition_id"]["value"], "ZOHO-2026-42")

    def test_14_document_extraction_txt_and_docx_and_invalid(self) -> None:
        r_txt = self.client.post(
            "/api/extract/document",
            files={"file": ("offer.txt", b"Company: Infosys\nRole: Analyst\nSalary: 6 LPA", "text/plain")},
        )
        self.assertEqual(r_txt.status_code, 200)
        self.assertEqual(r_txt.json()["file_type"], "txt")
        self.assertEqual(r_txt.json()["extracted_fields"]["employer"]["value"], "Infosys")

        doc = Document()
        doc.add_paragraph("Company: Wipro Limited")
        doc.add_paragraph("Role: Project Engineer")
        buf = io.BytesIO()
        doc.save(buf)
        r_docx = self.client.post(
            "/api/extract/document",
            files={
                "file": (
                    "offer.docx",
                    buf.getvalue(),
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            },
        )
        self.assertEqual(r_docx.status_code, 200)
        self.assertEqual(r_docx.json()["file_type"], "docx")
        self.assertIn("Wipro", r_docx.json()["extracted_text"])

        r_bad = self.client.post(
            "/api/extract/document",
            files={"file": ("malware.exe", b"MZ...", "application/octet-stream")},
        )
        self.assertEqual(r_bad.status_code, 400)

    def test_15_privacy_redaction(self) -> None:
        sample = "Aadhaar 2345 6789 0123, PAN ABCDE1234F, IFSC SBIN0001234, OTP is 482910, Account No: 123456789012"
        redacted, counts = redact_sensitive_info(sample)
        self.assertNotIn("2345 6789 0123", redacted)
        self.assertNotIn("ABCDE1234F", redacted)
        self.assertNotIn("SBIN0001234", redacted)
        self.assertNotIn("482910", redacted)
        self.assertNotIn("123456789012", redacted)
        self.assertGreaterEqual(len(counts), 4)

    def test_16_api_error_handling_empty_payload(self) -> None:
        r = self.client.post("/api/verify", json={"text": "   "})
        self.assertEqual(r.status_code, 400)

    def test_17_ml_info_transparent_metrics(self) -> None:
        r = self.client.get("/api/ml/info")
        self.assertEqual(r.status_code, 200)
        info = r.json()
        self.assertIn("evaluation_metrics", info)
        self.assertIn("limitation", info)

    # === MULTILINGUAL CALL RECORDING SCAM DETECTION TESTS ===
    def test_18_call_audio_wav_upload_metadata_and_honest_stt_status(self) -> None:
        wav_bytes = _make_sample_wav_bytes(duration_sec=0.5)
        r = self.client.post(
            "/api/call/analyze",
            files={"file": ("scam_call.wav", wav_bytes, "audio/wav")},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["audio_metadata"]["format"], "WAV")
        self.assertAlmostEqual(data["audio_metadata"]["duration_seconds"], 0.5, places=1)
        self.assertEqual(data["transcription_status"], EvidenceStatus.CHECK_UNAVAILABLE.value)

    def test_19_call_audio_with_english_scam_transcript(self) -> None:
        wav_bytes = _make_sample_wav_bytes(duration_sec=0.5)
        r = self.client.post(
            "/api/call/analyze",
            files={"file": ("hr_scam.wav", wav_bytes, "audio/wav")},
            data={
                "transcript": "Calling from Infosys HR. Pay ₹1,500 refundable registration fee to hr.verify@ybl and read me the 6-digit OTP. Do not hang up."
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["risk_level"], RiskLevel.HIGH.value)
        self.assertIn("hr.verify@ybl", data["extracted_entities"]["upi_ids_mentioned"])
        self.assertGreaterEqual(data["indicator_count"], 3)

    def test_20_call_multilingual_hindi_tamil_spanish_french(self) -> None:
        cases = [
            ("hi", "मैं सीबीआई अधिकारी बोल रहा हूँ। आप डिजिटल अरेस्ट में हैं। फोन मत काटना और ओटीपी बताइए।"),
            ("ta", "உங்களுக்கு வேலை உறுதியாகிவிட்டது. ₹1,500 ரெஜிஸ்ட்ரேஷன் கட்டணம் செலுத்தவும் மற்றும் ஓடிபி சொல்லுங்கள்."),
            ("es", "Hola, trabajo sin entrevista. Paga una tarifa de registro de $150 y dame el código OTP. No cuelgues."),
            ("fr", "Bonjour, embauché sans entretien. Payez les frais d'inscription et donnez-moi le code OTP. Ne raccrochez pas."),
        ]
        for expected_lang, text in cases:
            r = self.client.post("/api/call/analyze-transcript", json={"transcript": text})
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertEqual(data["detected_language_code"], expected_lang, f"Failed language for {expected_lang}")
            self.assertEqual(data["risk_level"], RiskLevel.HIGH.value, f"Failed risk for {expected_lang}")

    def test_21_call_legitimate_hr_with_disclaimer_low_risk(self) -> None:
        r = self.client.post(
            "/api/call/analyze-transcript",
            json={
                "transcript": "Hi Priya, calling from Razorpay Recruiting to schedule your interview on Thursday. Reminder: we do not charge any fee and never share your OTP or UPI PIN."
            },
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["risk_level"], RiskLevel.LOW.value)
        self.assertEqual(data["indicator_count"], 0)

    def test_22_call_invalid_audio_format_rejected(self) -> None:
        r = self.client.post(
            "/api/call/analyze",
            files={"file": ("not_audio.exe", b"MZ...", "application/octet-stream")},
        )
        self.assertEqual(r.status_code, 400)

    # === JSON HANDLING & COMPLETE AUTHENTICATION / EVIDENCE LIFECYCLE TESTS ===
    def test_23_json_document_upload_and_extraction(self) -> None:
        json_content = json.dumps({
            "employer": "TechCorp India",
            "role": "Senior Cloud Architect",
            "salary": "35 LPA",
            "location": "Bengaluru",
            "recruiter_email": "careers@techcorp.in",
        }).encode("utf-8")
        r = self.client.post(
            "/api/extract/document",
            files={"file": ("job_offer.json", json_content, "application/json")},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data["file_type"], "json")
        self.assertIn("TechCorp India", data["extracted_text"])

    def test_24_auth_lifecycle_register_login_verify_email_json_profile_password_delete(self) -> None:
        import uuid
        test_email = f"user_{uuid.uuid4().hex[:8]}@example.com"
        test_pwd = "StrongPass2026!#"

        # 1. Register
        reg_resp = self.client.post(
            "/api/auth/register",
            json={
                "full_name": "Test Candidate",
                "email": test_email,
                "mobile": "+91 98765 43210",
                "password": test_pwd,
                "terms_accepted": True,
            },
        )
        self.assertEqual(reg_resp.status_code, 200)
        user_info = reg_resp.json()["user"]
        self.assertEqual(user_info["email"], test_email)
        self.assertNotIn("token", reg_resp.json()["email_verification"])

        # 2. Verify Email with a server-issued one-time token
        verif_token = issue_auth_token(user_info["id"], "email_verify", 60 * 60)
        verif_resp = self.client.post("/api/auth/verify-email", json={"token": verif_token})
        self.assertEqual(verif_resp.status_code, 200)
        self.assertTrue(verif_resp.json()["verified"])

        # 3. Login
        login_resp = self.client.post(
            "/api/auth/login",
            json={"email": test_email, "password": test_pwd, "remember_me": True},
        )
        self.assertEqual(login_resp.status_code, 200)

        # 4. Check /api/auth/me session
        me_resp = self.client.get("/api/auth/me")
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["user"]["email"], test_email)

        # 5. Profile update
        prof_resp = self.client.patch(
            "/api/auth/profile",
            json={"full_name": "Updated Candidate", "mobile": "+91 99999 88888", "notifications": True},
        )
        self.assertEqual(prof_resp.status_code, 200)
        self.assertEqual(prof_resp.json()["user"]["full_name"], "Updated Candidate")

        # 6. Change password
        new_pwd = "NewSecurePass2026!#"
        pwd_resp = self.client.post(
            "/api/auth/password",
            json={"current_password": test_pwd, "new_password": new_pwd},
        )
        self.assertEqual(pwd_resp.status_code, 200)
        self.assertTrue(pwd_resp.json()["changed"])

        # 7. Saved Reports CRUD (user isolated evidence)
        sample_report = {"report_id": f"jg-test-{uuid.uuid4().hex[:6]}", "risk_level": "HIGH RISK", "risk_index": 85}
        save_resp = self.client.post(
            "/api/reports/save",
            json={"report": sample_report, "report_id": sample_report["report_id"]},
        )
        self.assertEqual(save_resp.status_code, 200)

        get_reps = self.client.get("/api/reports")
        self.assertEqual(get_reps.status_code, 200)
        reports_list = get_reps.json()["reports"]
        self.assertTrue(any(r["id"] == sample_report["report_id"] for r in reports_list))

        del_rep = self.client.delete(f"/api/reports/{sample_report['report_id']}")
        self.assertEqual(del_rep.status_code, 200)

        # 8. Delete user account
        del_user = self.client.delete("/api/auth/account")
        self.assertEqual(del_user.status_code, 200)

    def test_25_fraud_intelligence_upi_qr_audio_assessment_and_community(self) -> None:
        # UPI payment scam detection
        upi_res = self.client.post(
            "/api/fraud/intelligence",
            json={"text": "Selected for role. Pay ₹2,500 security deposit to upi:hr.security@ybl", "input_type": "payment"},
        )
        self.assertEqual(upi_res.status_code, 200)
        self.assertIn(upi_res.json()["risk_category"], ("SUSPICIOUS", "HIGH RISK", "CRITICAL"))

        # Audio assessment
        wav_bytes = _make_sample_wav_bytes(duration_sec=0.2)
        audio_res = self.client.post(
            "/api/fraud/audio-assessment",
            files={"file": ("voice_note.wav", wav_bytes, "audio/wav")},
        )
        self.assertEqual(audio_res.status_code, 200)
        self.assertIn("status", audio_res.json())

        # Community report submit and search
        comm_sub = self.client.post(
            "/api/community/report",
            json={"indicator": "fake.recruiter@hdfc-verify.xyz", "report_type": "phishing", "description": "Fake HR"},
        )
        self.assertEqual(comm_sub.status_code, 200)
        self.assertGreaterEqual(comm_sub.json()["reports"], 1)

        comm_search = self.client.get("/api/community/search?q=hdfc-verify.xyz")
        self.assertEqual(comm_search.status_code, 200)
        self.assertGreaterEqual(len(comm_search.json()["reports"]), 1)

    def test_26_secure_recovery_tokens_and_report_ownership(self) -> None:
        import uuid
        email_a = f"a_{uuid.uuid4().hex[:8]}@example.com"
        email_b = f"b_{uuid.uuid4().hex[:8]}@example.com"

        for email in (email_a, email_b):
            reg = self.client.post(
                "/api/auth/register",
                json={
                    "full_name": "Token Test",
                    "email": email,
                    "mobile": "",
                    "password": "StrongPass2026!#",
                    "terms_accepted": True,
                },
            )
            self.assertEqual(reg.status_code, 200)
            self.client.post("/api/auth/logout")

        forgot = self.client.post("/api/auth/forgot-password", json={"email": "missing@example.com"})
        self.assertEqual(forgot.status_code, 200)
        self.assertIn("delivery_available", forgot.json())

        reg_a = self.client.post(
            "/api/auth/login",
            json={"email": email_a, "password": "StrongPass2026!#", "remember_me": False},
        )
        self.assertEqual(reg_a.status_code, 200)
        me_a = self.client.get("/api/auth/me").json()["user"]
        report_id = f"jg-owner-{uuid.uuid4().hex[:8]}"
        save = self.client.post("/api/reports/save", json={"report": {"report_id": report_id}, "report_id": report_id})
        self.assertEqual(save.status_code, 200)

        self.client.post("/api/auth/logout")
        login_b = self.client.post(
            "/api/auth/login",
            json={"email": email_b, "password": "StrongPass2026!#", "remember_me": False},
        )
        self.assertEqual(login_b.status_code, 200)
        denied = self.client.delete(f"/api/reports/{report_id}")
        self.assertEqual(denied.status_code, 404)

        reset_token = issue_auth_token(me_a["id"], "password_reset", 3600)
        reset = self.client.post(
            "/api/auth/reset-password",
            json={"token": reset_token, "new_password": "ChangedPass2026!#"},
        )
        self.assertEqual(reset.status_code, 200)
        reused = self.client.post(
            "/api/auth/reset-password",
            json={"token": reset_token, "new_password": "AnotherPass2026!#"},
        )
        self.assertEqual(reused.status_code, 400)

    def test_27_report_id_collision_cross_user_and_invalid_pdf_content(self) -> None:
        import uuid
        email_a = f"collision_a_{uuid.uuid4().hex[:8]}@example.com"
        email_b = f"collision_b_{uuid.uuid4().hex[:8]}@example.com"

        for email in (email_a, email_b):
            response = self.client.post(
                "/api/auth/register",
                json={
                    "full_name": "Collision Test",
                    "email": email,
                    "mobile": "",
                    "password": "StrongPass2026!#",
                    "terms_accepted": True,
                },
            )
            self.assertEqual(response.status_code, 200)
            self.client.post("/api/auth/logout")

        self.client.post("/api/auth/login", json={"email": email_a, "password": "StrongPass2026!#"})
        collision_id = f"jg-collision-{uuid.uuid4().hex[:8]}"
        saved = self.client.post(
            "/api/reports/save",
            json={"report": {"report_id": collision_id}, "report_id": collision_id},
        )
        self.assertEqual(saved.status_code, 200)
        self.client.post("/api/auth/logout")

        self.client.post("/api/auth/login", json={"email": email_b, "password": "StrongPass2026!#"})
        collision = self.client.post(
            "/api/reports/save",
            json={"report": {"report_id": collision_id}, "report_id": collision_id},
        )
        self.assertEqual(collision.status_code, 409)

        invalid_pdf = self.client.post(
            "/api/extract/document",
            files={"file": ("fake.pdf", b"not actually a pdf", "application/pdf")},
        )
        self.assertEqual(invalid_pdf.status_code, 400)


if __name__ == "__main__":
    unittest.main()
