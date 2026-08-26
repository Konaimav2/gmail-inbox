#!/usr/bin/env python3
"""Audio reCAPTCHA solver helper — standalone stdin/stdout bridge for Node run-batch.

Input  (JSON on stdin): {"audio_url": "https://...mp3", "attempts": 4}
Output (JSON on stdout): {"ok": bool, "answer": str, "error": str}

Reuses the exact proven pipeline from th-webshare._solve_recaptcha_audio:
MP3 -> ffmpeg -> WAV -> Google Speech Recognition -> answer text.
"""
import json
import sys
import time
from pathlib import Path

BASE = Path("/root/temp/token-harbor")


def solve(audio_url, attempts=4):
    for attempt in range(1, attempts + 1):
        try:
            import speech_recognition as sr
            rec = sr.Recognizer()
        except Exception as e:
            return {"ok": False, "error": f"sr import: {e}"}
        try:
            import requests as _rq
            audio_bytes = _rq.get(audio_url, timeout=20,
                                  headers={"User-Agent": "Mozilla/5.0"}).content
            mp3 = str(BASE / "_captcha_audio.mp3")
            wav = str(BASE / "_captcha_audio.wav")
            with open(mp3, "wb") as f:
                f.write(audio_bytes)
            from pydub import AudioSegment
            AudioSegment.from_file(mp3).export(wav, format="wav")

            with sr.AudioFile(wav) as source:
                audio = rec.record(source)
            try:
                answer = rec.recognize_google(audio, language="en-US")
            except Exception as e:
                print(f"[solver] transcription {attempt}: {str(e)[:60]}", file=sys.stderr)
                time.sleep(1)
                continue
            if answer.strip():
                return {"ok": True, "answer": answer.strip().lower()}
        except Exception as e:
            print(f"[solver] attempt {attempt} error: {str(e)[:80]}", file=sys.stderr)
            time.sleep(1)
    return {"ok": False, "error": "all attempts failed"}


def main():
    data = json.load(sys.stdin)
    url = data.get("audio_url", "")
    if not url:
        print(json.dumps({"ok": False, "error": "no audio_url"}))
        return
    res = solve(url, data.get("attempts", 4))
    print(json.dumps(res), flush=True)


if __name__ == "__main__":
    main()
