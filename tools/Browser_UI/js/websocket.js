async function uploadFileViaWS(file, url, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";

    const waitAck = new Promise((innerResolve, innerReject) => {
      const timer = setTimeout(() => {
        innerReject(new Error("Timeout waiting for server response"));
        ws.close();
      }, timeout);

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "ack") {
            clearTimeout(timer);
            innerResolve({ success: true, data });
          } else if (data.type === "error") {
            clearTimeout(timer);
            innerResolve({ success: false, data });
          }
        } catch (err) {
	   
        }
      };

      ws.onerror = (e) => {
        clearTimeout(timer);
        innerReject(new Error("WebSocket error"));
      };

      ws.onclose = (e) => {
        clearTimeout(timer);
        innerReject(new Error("WebSocket closed"));
      };
    });

    ws.onopen = async () => {
      try {
        ws.send(JSON.stringify({
          type: "file_meta",
          filename: file.name,
          size: file.size,
          mime: file.type
        }));

        const buffer = await file.arrayBuffer();
        ws.send(buffer);
        const response = await waitAck;

        ws.close();

        resolve(response);

      } catch (err) {
        ws.close();
        reject(err);
      }
    };
  });
}

