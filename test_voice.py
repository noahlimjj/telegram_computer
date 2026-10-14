import io
import math
import struct
import wave
import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
from pathlib import Path
from transcribe_audio import transcribe_audio_file, get_whisper_model

def test_transcription():
    print("1. Initializing Whisper model...")
    model = get_whisper_model()
    assert model is not None, "Model failed to load"
    print("✅ Model loaded.")

    print("2. Generating test audio...")
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(16000)
        # 1.5 seconds of audio
        frames = bytearray()
        for t in range(24000):
            val = int(16000.0 * math.sin(2.0 * math.pi * 440.0 * t / 16000.0))
            frames.extend(struct.pack("<h", val))
        wav.writeframes(frames)
    
    test_wav = Path("test_sample.wav")
    test_wav.write_bytes(buf.getvalue())
    print(f"✅ Created test audio ({test_wav.stat().st_size} bytes).")

    print("3. Testing transcription...")
    res = transcribe_audio_file(test_wav)
    print(f"✅ Transcription completed cleanly (result: '{res}').")

    if test_wav.exists():
        test_wav.unlink()

    print("\n🎉 ALL VOICE TRANSCRIPTION TESTS PASSED!")

if __name__ == "__main__":
    test_transcription()
