import asyncio
import json
import websockets
from pathlib import Path
from datetime import datetime

async def handler(ws):
    print("Client connected")
    file_info = None
    file_bytes = bytearray()

    async for message in ws:
        if isinstance(message, str):
            data = json.loads(message)

            if data.get("type") == "file_meta":
                file_info = data
                file_bytes.clear()
                print("Receiving file:", file_info["filename"])

        elif isinstance(message, bytes):
            file_bytes.extend(message)
            filename = file_info["filename"]
            print("Orignal file name:", filename, "size:", len(file_bytes))
            
            TMP_DIR = Path("./tmp")
            TMP_DIR.mkdir(exist_ok=True)
            now = datetime.now()
            time_str = now.strftime("%Y%m%d_%H%M%S")
            filename = filename.replace(".xml", "")
            tmp_name = f"{filename}_{time_str}.xml"
            tmp_path = TMP_DIR / tmp_name
            print("Saved file: ", tmp_path)

            with open(tmp_path, "wb") as f:
                f.write(file_bytes)

            await ws.send(json.dumps({
                "type": "ack",
                "filename": tmp_name,
                "size": len(file_bytes)
            }))

async def main():
    async with websockets.serve(handler, "0.0.0.0", 8765, max_size=None):
        print("WS server running at ws://localhost:8765")
        await asyncio.Future()

def start_ws():
     asyncio.run(main())

