#!/usr/bin/env python3
"""Audio reCAPTCHA solver helper — standalone stdin/stdout bridge for Node run-batch.

Input  (JSON on stdin): {"audio_url": "https://...mp3", "attempts": 4}
Output (JSON on stdout): {"ok": bool, "answer": str, "error": str}

Reuses the exact proven pipeline from th-webshare._solve_recaptcha_audio:
MP3 -> ffmpeg -> WAV -> Google Speech Recognition -> answer text.
"""
import json
import os
import sys
import tempfile
import time

MAX_AUDIO_BYTES = 5 * 1024 * 1024  # ~5MB download cap


def _download_capped(audio_url, timeout=20):
    import requests as _rq
    with _rq.get(audio_url, timeout=timeout, stream=True,
                 headers={"User-Agent": "Mozilla/5.0"}) as r:
        r.raise_for_status()
        clen = r.headers.get("Content-Length")
        if clen is not None:
            try:
                clen = int(clen)
            except (TypeError, ValueError):
                clen = None
            if clen is not None and clen > MAX_AUDIO_BYTES:
                raise ValueError(f"audio too large (Content-Length {clen} > 5MB cap)")
        chunks = []
        total = 0
        for chunk in r.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_AUDIO_BYTES:
                raise ValueError("audio too large (> 5MB cap)")
            chunks.append(chunk)
    return b"".join(chunks)


def solve(audio_url, attempts=4):
    for attempt in range(1, attempts + 1):
        mp3_path = None
        wav_path = None
        try:
            import speech_recognition as sr
            rec = sr.Recognizer()
        except Exception as e:
            return {"ok": False, "error": f"sr import: {e}"}
        try:
            audio_bytes = _download_capped(audio_url)
            with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as f:
                f.write(audio_bytes)
                mp3_path = f.name
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                wav_path = f.name
            from pydub import AudioSegment
            AudioSegment.from_file(mp3_path).export(wav_path, format="wav")

            with sr.AudioFile(wav_path) as source:
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
        finally:
            for _p in (mp3_path, wav_path):
                try:
                    if _p:
                        os.unlink(_p)
                except OSError:
                    pass
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
