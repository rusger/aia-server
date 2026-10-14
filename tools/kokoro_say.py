#!/usr/bin/env python3
"""Kokoro на сервере — третий, бесплатный резерв озвучки реплик ведущего в звонке (radio_call.go, 14.10.2026).

Одна реплика одним голосом в wav. Запуск из Go: nice -n 19 <dir>/venv/bin/python tools/kokoro_say.py <dir> <voice> <out.wav>
(текст — stdin). Один поток onnxruntime: на 2 ядрах сервера идут 9 станций Liquidsoap, эфир важнее скорости.
"""
import sys

import onnxruntime as ort
import soundfile as sf
from kokoro_onnx import Kokoro

model_dir, voice, out = sys.argv[1], sys.argv[2], sys.argv[3]
so = ort.SessionOptions()
so.intra_op_num_threads = 1
so.inter_op_num_threads = 1
sess = ort.InferenceSession(f"{model_dir}/kokoro-v1.0.onnx", sess_options=so, providers=["CPUExecutionProvider"])
k = Kokoro.from_session(sess, f"{model_dir}/voices-v1.0.bin")
samples, sr = k.create(sys.stdin.read().strip(), voice=voice, speed=0.92, lang="en-us")
sf.write(out, samples, sr)
