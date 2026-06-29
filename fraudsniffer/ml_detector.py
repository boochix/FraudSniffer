from __future__ import annotations

import math
from typing import Any, Dict, List, Optional


class DocumentAnomalyDetector:
    """An unsupervised statistical anomaly detector for document structural profiles.
    Evaluates text density, character distribution, formatting entropy, and numeric ratios
    to detect template generation, copy-paste artifacts, or text scraping anomalies.
    """

    @classmethod
    def extract_structural_features(cls, text: str) -> Dict[str, float]:
        """Extract statistical features from document text."""
        if not text:
            return {
                "text_length": 0.0,
                "entropy": 0.0,
                "digit_ratio": 0.0,
                "whitespace_ratio": 0.0,
                "unique_word_ratio": 0.0,
                "avg_line_length": 0.0,
            }

        char_count = len(text)
        words = text.split()
        word_count = len(words)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        line_count = len(lines)

        # 1. Shannon Entropy
        counts: Dict[str, int] = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        entropy = -sum((count / char_count) * math.log2(count / char_count) for count in counts.values())

        # 2. Digit Ratio
        digits = sum(1 for char in text if char.isdigit())
        digit_ratio = digits / char_count if char_count > 0 else 0.0

        # 3. Whitespace Ratio
        whitespaces = sum(1 for char in text if char.isspace())
        whitespace_ratio = whitespaces / char_count if char_count > 0 else 0.0

        # 4. Unique Word Ratio
        unique_words = len(set(words))
        unique_word_ratio = unique_words / word_count if word_count > 0 else 0.0

        # 5. Average Line Length
        avg_line_length = char_count / line_count if line_count > 0 else 0.0

        return {
            "text_length": float(char_count),
            "entropy": round(entropy, 4),
            "digit_ratio": round(digit_ratio, 4),
            "whitespace_ratio": round(whitespace_ratio, 4),
            "unique_word_ratio": round(unique_word_ratio, 4),
            "avg_line_length": round(avg_line_length, 4),
        }

    @classmethod
    def compute_anomaly_score(
        cls, features: Dict[str, float], historical_features: List[Dict[str, float]]
    ) -> tuple[float, list[str]]:
        """Compute an anomaly score using statistical distance (Z-score ensemble)
        against historical documents. If history is too small, return neutral 0.0.
        """
        if len(historical_features) < 5:
            return 0.0, []

        anomaly_points = 0.0
        deviations = []

        keys = ["text_length", "entropy", "digit_ratio", "whitespace_ratio", "unique_word_ratio", "avg_line_length"]
        for key in keys:
            values = [h[key] for h in historical_features if key in h]
            if not values:
                continue
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            std = math.sqrt(variance)

            val = features.get(key, 0.0)
            if std > 0.0001:
                z = abs(val - mean) / std
                if z > 3.0:
                    anomaly_points += 0.25
                    deviations.append(f"{key} deviates by {z:.1f} standard deviations from baseline (val: {val:.3f}, mean: {mean:.3f})")
            else:
                # If variance is zero, any change is suspicious
                if abs(val - mean) > 0.0001:
                    anomaly_points += 0.15
                    deviations.append(f"{key} changed from constant baseline (val: {val:.3f}, expected: {mean:.3f})")

        return min(anomaly_points, 1.0), deviations


class SalaryOutlierScorer:
    """Tracks salary baselines per company/employer to detect fraudulent pay inflating."""

    @classmethod
    def check_salary(
        cls, employer: str, salary: float, historical_salaries: Dict[str, List[float]]
    ) -> tuple[float, Optional[str]]:
        """Verify if the salary is an outlier for the given employer.
        Returns a risk contribution (0.0 to 0.4) and a description of the deviation.
        """
        if not employer or not salary:
            return 0.0, None

        emp_key = employer.strip().lower()
        salaries = historical_salaries.get(emp_key, [])
        if len(salaries) < 3:
            # Insufficient baseline data for specific company
            return 0.0, None

        mean = sum(salaries) / len(salaries)
        variance = sum((s - mean) ** 2 for s in salaries) / len(salaries)
        std = math.sqrt(variance)

        if std < 1000.0:
            # Low standard deviation, let's set a floor of 10% of mean
            std = max(mean * 0.10, 5000.0)

        z = (salary - mean) / std
        if z > 2.5:
            risk = min(0.35, (z - 2.5) * 0.10 + 0.15)
            return risk, f"Salary (Rs. {salary:,.2f}) is an extreme outlier for {employer} (mean: Rs. {mean:,.2f}, std: Rs. {std:,.2f}, z: {z:.2f})"
        elif z < -2.5:
            # Substantially lower could mean demotion or invalid entry
            risk = 0.15
            return risk, f"Salary (Rs. {salary:,.2f}) is significantly lower than average for {employer} (mean: Rs. {mean:,.2f})"

        return 0.0, None
