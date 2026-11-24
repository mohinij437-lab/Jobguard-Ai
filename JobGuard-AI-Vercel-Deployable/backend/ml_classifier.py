"""Secondary ML Layer: Reproducible Pure-Python TF-IDF + Logistic Regression Classifier.

Trains deterministically at startup on a small, transparently disclosed synthetic labeled dataset
(English, Hindi, and Hinglish recruitment examples). Never fabricates evaluation metrics: all
reported metrics are computed directly on a fixed held-out split, and the small synthetic dataset
limitation is explicitly disclosed in every report.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from functools import lru_cache
from typing import Dict, List, Tuple

from .schemas import MLAssessment

# Small, reproducible labeled synthetic corpus (1 = fraudulent/scam, 0 = legitimate recruitment)
LABELED_SYNTHETIC_DATASET: List[Tuple[str, int]] = [
    # Fraudulent examples (label = 1)
    ("Pay Rs 999 refundable registration fee today to confirm your WFH job selection without interview.", 1),
    ("Job ke liye pehle 1500 registration fees jama karo aur direct joining letter pao.", 1),
    ("Earn Rs 5000 to 8000 daily by liking YouTube videos and rating Google Maps hotels on Telegram.", 1),
    ("Complete 3 VIP prepaid merchant tasks and recharge wallet to unlock your frozen salary payout.", 1),
    ("Congratulations you are selected without interview. Pay Rs 2500 security deposit for laptop kit.", 1),
    ("बिना इंटरव्यू के नौकरी पाने के लिए सिक्योरिटी डिपॉजिट दें और आज ही जॉइन करें।", 1),
    ("Install AnyDesk and share the 9 digit code with HR for salary account verification.", 1),
    ("Share your 6 digit OTP and UPI PIN to verify your bank account for stipend credit.", 1),
    ("Urgent hiring at Infosys apply on infosys.careers-verification.xyz and pay 500 processing fee.", 1),
    ("Mandatory paid training fee of Rs 4000 before joining for guaranteed internship certificate.", 1),
    ("Part time work from home earn 6000 per day no skills required message only on WhatsApp.", 1),
    ("Pay 750 document verification fee within 2 hours or your job offer will be cancelled.", 1),
    ("Ghar baithe roz 4000 kamayein bina interview ke direct selection telegram group join karo.", 1),
    ("Transfer Rs 1200 refundable security deposit to HR UPI ID to schedule your final interview.", 1),
    ("VIP Telegram task group guaranteed daily income recharge 3000 to withdraw 4500 bonus.", 1),
    ("रजिस्ट्रेशन फीस जमा करें और बिना इंटरव्यू के सीधी भर्ती पाएं।", 1),
    # Legitimate examples (label = 0)
    ("Infosys is hiring Software Engineers in Bengaluru. Apply via infosys.com/careers. We never charge any registration fee.", 0),
    ("Thank you for applying for Backend Developer at Razorpay. Your technical interview is scheduled for Thursday at 3 PM.", 0),
    ("Urgent reminder: please submit your updated resume before Friday for the Data Analyst interview panel.", 0),
    ("TCS does not charge any fee at any stage of the recruitment process. Apply only on tcs.com/careers.", 0),
    ("We are looking for a Frontend Engineer with 2+ years React experience. Salary 12-16 LPA. Location Pune Hybrid.", 0),
    ("Summer Internship Program at Zoho Corporation. Stipend Rs 25000 per month. Technical assessment followed by 2 interviews.", 0),
    ("Hi Priya, following up on your application for Product Designer (Req ID: REQ-4421). Let us know your availability.", 0),
    ("Wipro Campus Hiring 2026. Eligibility B.Tech CSE/IT. Zero fees. Official communications only from @wipro.com.", 0),
    ("Notice: Never pay any registration fee or security deposit during recruitment. Report fake recruiters to HR.", 0),
    ("We reviewed your GitHub portfolio and would like to invite you to a 45-minute coding round via Google Meet.", 0),
    ("Open role: Junior Python Developer at Acme Labs, Noida. Full-time on-site. Send resume to careers@acmelabs.in.", 0),
    ("Your interview feedback is positive. HR will share the formal offer letter from @accenture.com next week.", 0),
    ("भर्ती के दौरान कोई शुल्क नहीं लिया जाता है। कृपया केवल आधिकारिक वेबसाइट पर आवेदन करें।", 0),
    ("Graduate Engineer Trainee opening in Hyderabad. 6.5 LPA CTC. Selection via online test and technical interview.", 0),
    ("Freelance UI/UX contract for 3 months. Hourly rate discussed during discovery call. Portfolio review required.", 0),
    ("Reminder: Campus placement pre-placement talk starts at 10 AM in Auditorium B. Carry your college ID card.", 0),
]

TOKEN_RE = re.compile(r"[a-zA-Z0-9\u0900-\u097F]{2,}")


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in TOKEN_RE.findall(text or "")]


class PurePythonTFIDFLogReg:
    """Deterministic TF-IDF + L2-regularized Logistic Regression in pure Python."""

    def __init__(self) -> None:
        self.vocab: Dict[str, int] = {}
        self.inv_vocab: Dict[int, str] = {}
        self.idf: List[float] = []
        self.weights: List[float] = []
        self.bias: float = 0.0
        self.metrics: Dict[str, object] = {}
        self._train_and_evaluate()

    def _fit(self, docs: List[Tuple[str, int]], epochs: int = 120, lr: float = 0.6, l2: float = 0.005) -> None:
        tokenized = [_tokenize(text) for text, _ in docs]
        df: Counter = Counter()
        for toks in tokenized:
            for tok in set(toks):
                df[tok] += 1
        self.vocab = {tok: idx for idx, (tok, _) in enumerate(sorted(df.items()))}
        self.inv_vocab = {idx: tok for tok, idx in self.vocab.items()}
        n_docs = len(docs)
        self.idf = [0.0] * len(self.vocab)
        for tok, idx in self.vocab.items():
            self.idf[idx] = math.log((1 + n_docs) / (1 + df[tok])) + 1.0

        vectors = [self._vectorize_tokens(toks) for toks in tokenized]
        self.weights = [0.0] * len(self.vocab)
        self.bias = 0.0

        for _ in range(epochs):
            grad_w = [0.0] * len(self.vocab)
            grad_b = 0.0
            for vec, (_, label) in zip(vectors, docs):
                z = self.bias + sum(self.weights[i] * v for i, v in vec.items())
                p = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, z))))
                err = p - label
                grad_b += err
                for i, v in vec.items():
                    grad_w[i] += err * v
            for i in range(len(self.weights)):
                self.weights[i] -= lr * (grad_w[i] / n_docs + l2 * self.weights[i])
            self.bias -= lr * (grad_b / n_docs)

    def _vectorize_tokens(self, toks: List[str]) -> Dict[int, float]:
        counts = Counter(t for t in toks if t in self.vocab)
        if not counts:
            return {}
        total = sum(counts.values())
        vec = {self.vocab[t]: (c / total) * self.idf[self.vocab[t]] for t, c in counts.items()}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {i: v / norm for i, v in vec.items()}

    def _train_and_evaluate(self) -> None:
        # Deterministic 75/25 stratified split (every 4th sample held out)
        train_docs: List[Tuple[str, int]] = []
        test_docs: List[Tuple[str, int]] = []
        for idx, item in enumerate(LABELED_SYNTHETIC_DATASET):
            if idx % 4 == 3:
                test_docs.append(item)
            else:
                train_docs.append(item)

        self._fit(train_docs)
        tp = fp = tn = fn = 0
        for text, y_true in test_docs:
            prob, _ = self.predict_proba(text)
            y_pred = 1 if prob >= 0.5 else 0
            if y_true == 1 and y_pred == 1:
                tp += 1
            elif y_true == 0 and y_pred == 1:
                fp += 1
            elif y_true == 0 and y_pred == 0:
                tn += 1
            else:
                fn += 1

        total = len(test_docs)
        acc = (tp + tn) / total if total else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0

        self.metrics = {
            "train_samples": len(train_docs),
            "test_samples": len(test_docs),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "heldout_accuracy": round(acc, 3),
            "heldout_precision": round(prec, 3),
            "heldout_recall": round(rec, 3),
            "heldout_f1": round(f1, 3),
            "note": "Computed on a small 32-sample synthetic benchmark; not a real-world production benchmark.",
        }
        # Refit on full synthetic corpus for inference
        self._fit(LABELED_SYNTHETIC_DATASET)

    def predict_proba(self, text: str) -> Tuple[float, List[str]]:
        toks = _tokenize(text)
        vec = self._vectorize_tokens(toks)
        if not vec:
            return 0.5, []
        z = self.bias + sum(self.weights[i] * v for i, v in vec.items())
        prob = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, z))))
        contribs = sorted(
            ((self.weights[i] * v, self.inv_vocab[i]) for i, v in vec.items()),
            key=lambda x: abs(x[0]),
            reverse=True,
        )
        top_terms = [f"{tok} ({'+' if score >= 0 else ''}{score:.2f})" for score, tok in contribs[:5]]
        return round(prob, 3), top_terms


_CLASSIFIER = PurePythonTFIDFLogReg()


@lru_cache(maxsize=256)
def run_ml_classification(text: str) -> MLAssessment:
    """Run secondary TF-IDF + Logistic Regression assessment with transparent disclosure."""
    prob, top_terms = _CLASSIFIER.predict_proba(text or "")
    label = (
        "Elevated Scam Text Pattern"
        if prob >= 0.65
        else "Ambiguous / Insufficient Text Signal"
        if prob >= 0.35
        else "Low Scam Text Pattern"
    )
    return MLAssessment(
        available=True,
        model_type="TF-IDF + L2 Logistic Regression (Pure Python Secondary Classifier)",
        predicted_label=label,
        scam_probability_estimate=prob,
        top_contributing_terms=top_terms,
        dataset_disclosure=(
            "Secondary heuristic model trained on a small 32-sample synthetic EN/HI/Hinglish dataset. "
            "It serves strictly as a supporting signal alongside deterministic rules and structured evidence, "
            "not as a calibrated real-world fraud probability."
        ),
        evaluation_metrics=_CLASSIFIER.metrics,
    )


def get_ml_metadata() -> Dict[str, object]:
    return {
        "model_type": "TF-IDF + L2 Logistic Regression (Pure Python)",
        "total_synthetic_samples": len(LABELED_SYNTHETIC_DATASET),
        "vocab_size": len(_CLASSIFIER.vocab),
        "evaluation_metrics": _CLASSIFIER.metrics,
        "limitation": "Trained on a small synthetic dataset for reproducibility; primary decisions rely on deterministic evidence rules and URL/domain verification.",
    }
