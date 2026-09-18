from collections import Counter
from dataclasses import dataclass
from math import log2


@dataclass
class DNSFeatures:
    """
    Numerical features extracted from a DNS query name.

    These features are designed to support passive detection of
    DGA domains and DNS tunnelling without inspecting payloads
    beyond the observed DNS query metadata.
    """

    query: str

    query_length: int
    label_count: int
    max_label_length: int
    average_label_length: float

    entropy: float
    digit_ratio: float
    unique_char_ratio: float

    vowel_ratio: float
    consonant_ratio: float

    hyphen_ratio: float
    numeric_label_count: int

    subdomain_depth: int


class DNSFeatureExtractor:
    """
    Extract statistical features from an observed DNS query name.

    The extractor is purely analytical and does not perform DNS
    lookups or any network interaction.
    """

    @staticmethod
    def extract(query: str) -> DNSFeatures:
        normalized = query.strip().lower().rstrip(".")

        if not normalized:
            return DNSFeatures(
                query=query,
                query_length=0,
                label_count=0,
                max_label_length=0,
                average_label_length=0.0,
                entropy=0.0,
                digit_ratio=0.0,
                unique_char_ratio=0.0,
                vowel_ratio=0.0,
                consonant_ratio=0.0,
                hyphen_ratio=0.0,
                numeric_label_count=0,
                subdomain_depth=0,
            )

        labels = [
            label
            for label in normalized.split(".")
            if label
        ]

        characters = [
            char
            for char in normalized
            if char != "."
        ]

        query_length = len(characters)

        label_lengths = [
            len(label)
            for label in labels
        ]

        max_label_length = max(label_lengths)
        average_label_length = (
            sum(label_lengths) / len(label_lengths)
        )

        entropy = DNSFeatureExtractor._entropy(
            characters
        )

        digit_count = sum(
            char.isdigit()
            for char in characters
        )

        unique_char_count = len(set(characters))

        alphabetic_characters = [
            char
            for char in characters
            if char.isalpha()
        ]

        vowel_count = sum(
            char in "aeiou"
            for char in alphabetic_characters
        )

        consonant_count = sum(
            char.isalpha() and char not in "aeiou"
            for char in alphabetic_characters
        )

        hyphen_count = normalized.count("-")

        numeric_label_count = sum(
            label.isdigit()
            for label in labels
        )

        return DNSFeatures(
            query=query,

            query_length=query_length,
            label_count=len(labels),
            max_label_length=max_label_length,
            average_label_length=round(
                average_label_length,
                3,
            ),

            entropy=round(entropy, 3),
            digit_ratio=round(
                digit_count / query_length,
                3,
            ),
            unique_char_ratio=round(
                unique_char_count / query_length,
                3,
            ),

            vowel_ratio=round(
                vowel_count / max(len(alphabetic_characters), 1),
                3,
            ),
            consonant_ratio=round(
                consonant_count / max(len(alphabetic_characters), 1),
                3,
            ),

            hyphen_ratio=round(
                hyphen_count / query_length,
                3,
            ),
            numeric_label_count=numeric_label_count,

            subdomain_depth=max(len(labels) - 2, 0),
        )

    @staticmethod
    def _entropy(characters: list[str]) -> float:
        if not characters:
            return 0.0

        counts = Counter(characters)
        total = len(characters)

        return -sum(
            (count / total)
            * log2(count / total)
            for count in counts.values()
        )