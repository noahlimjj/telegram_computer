"""
transcribe_audio.py
High-speed local audio & voice note transcription engine using faster-whisper.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

# PyAV 14+ compatibility patch for faster-whisper
try:
    import av
    _orig_open = av.open
    def _patched_open(*args, **kwargs):
        kwargs.pop("metadata_errors", None)
        return _orig_open(*args, **kwargs)
    av.open = _patched_open
except Exception:
    pass

from faster_whisper import WhisperModel

_model: WhisperModel | None = None

def get_whisper_model() -> WhisperModel:
    global _model
    if _model is None:
        # i9-10900KF with 6 threads int8 runs base in ~0.3-0.5s
        _model = WhisperModel("base", device="cpu", compute_type="int8", cpu_threads=6)
    return _model

def transcribe_audio_file(file_path_or_bytes: str | Path | io.BytesIO | bytes) -> str:
    """Transcribe an audio file (e.g. Telegram .oga, .ogg, .mp3, .wav) to text."""
    model = get_whisper_model()
    
    if isinstance(file_path_or_bytes, bytes):
        audio_src = io.BytesIO(file_path_or_bytes)
    elif isinstance(file_path_or_bytes, (str, Path)):
        audio_src = str(file_path_or_bytes)
    else:
        audio_src = file_path_or_bytes

    segments, info = model.transcribe(audio_src, beam_size=3)
    text_parts = [segment.text.strip() for segment in segments]
    return " ".join(text_parts).strip()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = transcribe_audio_file(sys.argv[1])
        print(f"Transcribed:\n{result}")
    else:
        print("Usage: python transcribe_audio.py <audio_file>")
